#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Veil для Windows/Linux/macOS — tkinter-GUI поверх veil_core.

Запуск:  python veil_client.py
"""

import json
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

import veil_core as core

APP_TITLE = "Veil — мессенджер, устойчивый к блокировкам"


class VeilApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x600")
        self.minsize(700, 450)

        # VEIL_HOME позволяет держать отдельный каталог состояния
        # (несколько копий клиента на одной машине, тесты)
        state_dir = core.os.environ.get("VEIL_HOME") or core.default_state_dir()
        state_path = core.os.path.join(state_dir, "store.json")
        try:
            core.os.makedirs(state_dir, exist_ok=True)
        except OSError:
            pass
        self.state = core.ClientState(state_path)
        self.events = queue.Queue()
        # кортеж обязателен: put(kind, payload) унёс бы payload в block=
        self.core = core.VeilClientCore(
            self.state, on_event=lambda kind, payload: self.events.put((kind, payload)))
        self.current_chat = None  # sign_pub или None

        self._build_ui()
        self.after(150, self._drain_events)
        if self.state.identity is None:
            self.after(100, self._show_onboarding)
        else:
            self.core.start()

    # ------------------------------------------------------------ UI-каркас
    def _build_ui(self):
        toolbar = ttk.Frame(self)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=4)
        ttk.Button(toolbar, text="Мой профиль",
                   command=self._show_profile).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Добавить контакт",
                   command=self._show_add_contact).pack(side=tk.LEFT, padx=6)
        ttk.Button(toolbar, text="Реле…", command=self._show_relays).pack(side=tk.LEFT)

        main = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # левая колонка: список чатов
        left = ttk.Frame(main)
        ttk.Label(left, text="Чаты").pack(anchor=tk.W, padx=8, pady=(6, 0))
        self.chat_list = tk.Listbox(left, width=26, activestyle="dotbox")
        self.chat_list.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.chat_list.bind("<<ListboxSelect>>", self._on_chat_selected)
        main.add(left, weight=1)

        # правая колонка: переписка
        right = ttk.Frame(main)
        self.chat_header = ttk.Label(right, text="Выберите чат",
                                     font=("", 12, "bold"))
        self.chat_header.pack(anchor=tk.W, padx=10, pady=(8, 2))
        self.messages = scrolledtext.ScrolledText(
            right, wrap=tk.WORD, state=tk.DISABLED, font=("", 11))
        self.messages.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.messages.tag_configure("meta_in", foreground="#666666",
                                    lmargin1=8, lmargin2=8)
        self.messages.tag_configure("meta_out", foreground="#0066cc",
                                    justify=tk.RIGHT, rmargin=8)
        self.messages.tag_configure("body_in", lmargin1=8, lmargin2=8,
                                    spacing1=2, spacing3=6)
        self.messages.tag_configure("body_out", justify=tk.RIGHT, rmargin=8,
                                    spacing1=2, spacing3=6)
        input_row = ttk.Frame(right)
        input_row.pack(fill=tk.X, padx=8, pady=(0, 8))
        self.input = ttk.Entry(input_row, font=("", 11))
        self.input.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)
        self.input.bind("<Return>", lambda e: self._send())
        ttk.Button(input_row, text="Отправить ▶",
                   command=self._send).pack(side=tk.LEFT, padx=(8, 0))
        main.add(right, weight=3)

        # строка состояния
        self.status = ttk.Label(self, text="Готово", anchor=tk.W,
                                foreground="#666666")
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    # ------------------------------------------------------------ чаты
    def _chat_rows(self):
        """[(listbox label, chat_id)] — Избранное + контакты по свежести."""
        rows = []
        ident = self.state.identity
        if ident:
            rows.append(("★ Избранное", ident.sign_pub_hex))
        contacts = sorted(self.state.data["contacts"],
                          key=lambda c: c.get("lastMessageAt") or 0,
                          reverse=True)
        for c in contacts:
            last = ""
            for m in reversed(self.state.data["messages"]):
                if m["contactId"] == c["signPub"]:
                    last = " — " + (m["text"][:24] + ("…" if len(m["text"]) > 24 else ""))
                    break
            rows.append((c["name"] + last, c["signPub"]))
        return rows

    def refresh_chats(self, keep_selection=True):
        selected = self.current_chat
        self.chat_list.delete(0, tk.END)
        rows = self._chat_rows()
        for label, _ in rows:
            self.chat_list.insert(tk.END, label)
        if keep_selection and selected:
            for i, (_, chat_id) in enumerate(rows):
                if chat_id == selected:
                    self.chat_list.selection_set(i)
                    break

    def _on_chat_selected(self, _event):
        sel = self.chat_list.curselection()
        rows = self._chat_rows()
        if not sel or sel[0] >= len(rows):
            return
        self.current_chat = rows[sel[0]][1]
        self.render_chat()

    def render_chat(self):
        chat_id = self.current_chat
        self.messages.configure(state=tk.NORMAL)
        self.messages.delete("1.0", tk.END)
        if chat_id is None:
            self.messages.configure(state=tk.DISABLED)
            return
        ident = self.state.identity
        is_self = ident and chat_id == ident.sign_pub_hex
        contact = self.state.contact(chat_id)
        title = ("Избранное" if is_self
                 else (contact["name"] if contact else chat_id[:16] + "…"))
        subtitle = "ID: %s…" % chat_id[:16]
        if not is_self and contact:
            subtitle += " · реле: %s" % (len(contact.get("relays") or [])
                                         or "мои")
        self.chat_header.configure(text="%s   (%s)" % (title, subtitle))
        for m in sorted([m for m in self.state.data["messages"]
                         if m["contactId"] == chat_id], key=lambda m: m["ts"]):
            who = "Вы" if is_self else ("Вы" if not m["incoming"]
                                        else (contact["name"] if contact else "…"))
            stamp = time.strftime("%H:%M", time.localtime(m["ts"] / 1000.0))
            meta = "%s · %s %s" % (who, stamp,
                                   "" if m["incoming"] else ("✓✓" if m.get("delivered") else "✓…"))
            tag = "meta_out" if not m["incoming"] else "meta_in"
            body = "body_out" if not m["incoming"] else "body_in"
            self.messages.insert(tk.END, meta + "\n", tag)
            self.messages.insert(tk.END, m["text"] + "\n\n", body)
        self.messages.configure(state=tk.DISABLED)
        self.messages.yview_moveto(1.0)

    # ------------------------------------------------------------ события ядра
    def _drain_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind in ("message", "delivery", "contact"):
                    self.refresh_chats()
                    if self.current_chat is not None:
                        self.render_chat()
                elif kind == "sync":
                    ws_note = "WS" if core.HAVE_WS else "polling"
                    self.status.configure(
                        text="Синхронизировано %s · транспорт: %s"
                             % (time.strftime("%H:%M:%S"), ws_note))
                elif kind == "error":
                    self.status.configure(text="⚠ " + str(payload))
        except queue.Empty:
            pass
        self.after(150, self._drain_events)

    # ------------------------------------------------------------ отправка
    def _send(self):
        if self.current_chat is None or not self.state.identity:
            return
        text = self.input.get().strip()
        if not text:
            return
        self.input.delete(0, tk.END)
        chat_id = self.current_chat

        def worker():
            self.core.send_message(text, chat_id)

        threading.Thread(target=worker, daemon=True).start()
        self.render_chat()
        self.refresh_chats()

    # ------------------------------------------------------------ диалоги
    def _modal(self, title, width=420, height=300):
        win = tk.Toplevel(self)
        win.title(title)
        win.geometry("%dx%d" % (width, height))
        win.transient(self)
        win.grab_set()
        return win

    def _show_onboarding(self):
        win = self._modal("Добро пожаловать в Veil", 460, 260)
        ttk.Label(win, text="Veil — мессенджер, устойчивый к блокировкам.\n"
                            "Ключи создаются на этом устройстве и не покидают его.",
                  justify=tk.CENTER).pack(pady=12)
        name_var = tk.StringVar()
        ttk.Label(win, text="Ваше имя:").pack()
        ttk.Entry(win, textvariable=name_var, width=30).pack(pady=4)

        def create():
            identity = core.VeilIdentity.generate()
            self.state.set_identity(identity, name_var.get().strip() or "Я")
            win.destroy()
            self.core.start()
            self.refresh_chats()

        ttk.Button(win, text="Создать личность", command=create).pack(pady=10)

    def _show_profile(self):
        ident = self.state.identity
        if ident is None:
            messagebox.showinfo(APP_TITLE, "Сначала создайте личность")
            return
        win = self._modal("Мой профиль", 560, 420)
        ttk.Label(win, text="Имя:").pack(anchor=tk.W, padx=10)
        name_var = tk.StringVar(value=self.state.data.get("profileName", ""))
        name_entry = ttk.Entry(win, textvariable=name_var)
        name_entry.pack(fill=tk.X, padx=10)

        def save_name(*_):
            self.state.data["profileName"] = name_var.get().strip() or "Я"
            self.state.save()

        name_entry.bind("<FocusOut>", save_name)

        ttk.Label(win, text="ID: %s…" % ident.sign_pub_hex[:24],
                  font=("Courier", 9)).pack(anchor=tk.W, padx=10, pady=4)
        invite = core.encode_invite(
            self.state.data.get("profileName", ""),
            ident.sign_pub_hex, ident.x_pub_hex,
            self.state.enabled_relay_urls())
        ttk.Label(win, text="Код приглашения:").pack(anchor=tk.W, padx=10)
        box = scrolledtext.ScrolledText(win, height=6, width=60, wrap=tk.CHAR,
                                        font=("Courier", 8))
        box.insert("1.0", invite)
        box.configure(state=tk.DISABLED)
        box.pack(fill=tk.BOTH, expand=True, padx=10)

        def copy_invite():
            self.clipboard_clear()
            self.clipboard_append(invite)
            btn.configure(text="✓ Скопировано")

        btn = ttk.Button(win, text="Скопировать приглашение", command=copy_invite)
        btn.pack(pady=4)

        def export_identity():
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                initialfile="veil-identity-backup.json",
                filetypes=[("JSON", "*.json")])
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(ident.to_keys_dict(), f, indent=1)
                messagebox.showinfo(APP_TITLE, "Файл содержит приватные ключи — храните его в безопасности.")

        def import_identity():
            path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
            if not path:
                return
            try:
                with open(path, "r", encoding="utf-8") as f:
                    keys = json.load(f)
            except (OSError, ValueError):
                messagebox.showerror(APP_TITLE, "Не удалось прочитать файл")
                return
            identity = core.VeilIdentity.from_keys_dict(keys)
            if identity is None:
                messagebox.showerror(APP_TITLE, "Файл не похож на резервную копию Veil")
                return
            self.state.set_identity(identity, self.state.data.get("profileName", ""))
            messagebox.showinfo(APP_TITLE, "Личность импортирована (подходит и бэкап с macOS)")
            win.destroy()

        row = ttk.Frame(win)
        row.pack(pady=6)
        ttk.Button(row, text="Экспортировать личность…",
                   command=export_identity).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="Импортировать… (macOS-бэкап)",
                   command=import_identity).pack(side=tk.LEFT, padx=4)

    def _show_add_contact(self):
        win = self._modal("Добавить контакт", 520, 340)
        ttk.Label(win, text="Вставьте код приглашения:").pack(anchor=tk.W, padx=10,
                                                              pady=(8, 2))
        box = scrolledtext.ScrolledText(win, height=6, wrap=tk.CHAR,
                                        font=("Courier", 8))
        box.pack(fill=tk.BOTH, expand=True, padx=10)
        preview = ttk.Label(win, text="", foreground="#0066cc")
        preview.pack(anchor=tk.W, padx=10)

        def on_change(*_):
            inv = core.parse_invite(box.get("1.0", tk.END))
            if inv:
                preview.configure(text="Имя: %s · ID: %s… · реле: %s"
                                  % (inv.get("n") or "—", inv["s"][:12],
                                     ", ".join(inv.get("r", [])) or "нет"))
            else:
                s = box.get("1.0", tk.END).strip()
                preview.configure(text="" if not s else "Код не распознан")

        box.bind("<KeyRelease>", on_change)

        def add():
            inv = core.parse_invite(box.get("1.0", tk.END))
            if inv and self.state.add_contact_from_invite(inv):
                self.refresh_chats()
                win.destroy()

        ttk.Button(win, text="Добавить", command=add).pack(pady=8)

    def _show_relays(self):
        win = self._modal("Реле-серверы", 520, 320)
        ttk.Label(win, text="Relay хранит зашифрованные конверты и не читает сообщения. "
                            "Можно указать несколько.").pack(anchor=tk.W, padx=10,
                                                             pady=(8, 4))
        listbox = tk.Listbox(win, height=6)
        listbox.pack(fill=tk.BOTH, expand=True, padx=10)

        def refresh():
            listbox.delete(0, tk.END)
            for r in self.state.data["relays"]:
                listbox.insert(tk.END, ("%s  %s" % (
                    "[x]" if r.get("enabled", True) else "[ ]",
                    core.normalize_base(r["url"]))))

        refresh()
        entry_row = ttk.Frame(win)
        entry_row.pack(fill=tk.X, padx=10, pady=6)
        url_var = tk.StringVar()
        ttk.Entry(entry_row, textvariable=url_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True)

        def add_relay():
            if self.state.add_relay(url_var.get()):
                url_var.set("")
                refresh()

        def test_selected():
            sel = listbox.curselection()
            if not sel:
                return
            url = core.normalize_base(self.state.data["relays"][sel[0]]["url"])
            listbox.delete(sel[0])
            listbox.insert(sel[0], "проверяю %s…" % url)
            ok = core.RelayTransport.health(url)
            listbox.delete(sel[0])
            refresh()
            messagebox.showinfo(APP_TITLE, "%s — %s" % (
                url, "онлайн ✅" if ok else "нет ответа ❌"))

        def del_selected():
            sel = listbox.curselection()
            if sel:
                self.state.remove_relay(
                    core.normalize_base(self.state.data["relays"][sel[0]]["url"]))
                refresh()

        ttk.Button(entry_row, text="Добавить", command=add_relay).pack(
            side=tk.LEFT, padx=(6, 0))
        ttk.Button(entry_row, text="Проверить", command=test_selected).pack(
            side=tk.LEFT, padx=6)
        ttk.Button(entry_row, text="Удалить", command=del_selected).pack(
            side=tk.LEFT)


def main():
    app = VeilApp()
    app.mainloop()


if __name__ == "__main__":
    main()
