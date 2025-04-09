import base64
import os
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from xml.etree import ElementTree as ET
import zlib
import asyncio
import platform

MAX_VISIBLE_ITEMS = 300
SENSITIVE_KEYWORDS = ['password', 'secret', 'token', 'login']
current_file_path = None
original_xml = None
parsed_data = {}
visible_keys = []
all_widgets = []
entries_per_page = MAX_VISIBLE_ITEMS
sensitive_hidden = True
widget_refs = {}

def xor(data: bytes, key: int = 11) -> bytes:
    return bytes(b ^ key for b in data)

def decode_save(data: bytes) -> str:
    decrypted = xor(data, 11)
    decoded = base64.b64decode(decrypted, altchars=b'-_')
    decompressed = zlib.decompress(decoded[10:], wbits=-15)
    try:
        return decompressed.decode('utf-8')
    except UnicodeDecodeError:
        return decompressed.decode('latin1')

def encode_save(xml_data: str) -> bytes:
    raw = xml_data.encode('utf-8')
    compressed = zlib.compress(raw)
    crc32 = zlib.crc32(raw)
    size = len(raw)
    gzip_data = (
        b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x0b' +
        compressed[2:-4] +
        struct.pack('<II', crc32, size)
    )
    b64 = base64.b64encode(gzip_data, altchars=b'-_')
    return xor(b64, 11)

def parse_dict(element, prefix=""):
    result = {}
    children = list(element)
    i = 0
    while i < len(children) - 1:
        key_elem = children[i]
        val_elem = children[i + 1]
        i += 2
        if key_elem.tag != 'k':
            continue
        key = key_elem.text
        full_key = f"{prefix}/{key}" if prefix else key
        if val_elem.tag in ('dict', 'd'):
            nested = parse_dict(val_elem, full_key)
            result.update(nested)
        else:
            result[full_key] = val_elem.text or ""
    return result

def build_editor_from_xml(xml_string):
    global parsed_data, visible_keys, all_widgets, original_xml
    root = ET.fromstring(xml_string)
    dict_elem = root.find('dict')
    if dict_elem is None:
        raise ValueError("Could not find <dict> in XML.")
    parsed_data = parse_dict(dict_elem)
    visible_keys = list(parsed_data.keys())
    original_xml = xml_string
    display_entries()

def display_entries(reset=False):
    for widget in all_widgets:
        widget.destroy()
    all_widgets.clear()
    widget_refs.clear()
    editor_canvas.yview_moveto(0)
    display_count = len(visible_keys) if reset or search_var.get() else entries_per_page
    keys_to_show = visible_keys[:display_count]
    for key in keys_to_show:
        if sensitive_hidden and any(k in key.lower() for k in SENSITIVE_KEYWORDS):
            continue
        val = parsed_data.get(key, "")
        frame = tk.Frame(scrollable_frame, bg="#f0f0f0")
        frame.pack(fill=tk.X, padx=5, pady=2)
        label = tk.Label(frame, text=key, anchor="w", width=40, bg="#f0f0f0")
        label.pack(side=tk.LEFT)

        # Type detection
        if str(val).lower() in ['true', 'false', '1', '0']:
            var = tk.BooleanVar(value=(str(val).lower() in ['true', '1']))
            cb = tk.Checkbutton(frame, variable=var)
            cb.pack(side=tk.RIGHT)
            widget_refs[key] = ('bool', var)
        elif str(val).replace('.', '', 1).isdigit():
            entry = tk.Entry(frame, validate="key")
            entry.insert(0, str(val))
            entry['validatecommand'] = (entry.register(lambda s: s == "" or s.replace('.', '', 1).isdigit()), "%P")
            entry.pack(fill=tk.X, expand=True, side=tk.RIGHT)
            widget_refs[key] = ('number', entry)
        else:
            entry = tk.Entry(frame)
            entry.insert(0, str(val))
            entry.pack(fill=tk.X, expand=True, side=tk.RIGHT)
            widget_refs[key] = ('string', entry)
        all_widgets.append(frame)

def on_search(*args):
    global visible_keys
    query = search_var.get().lower()
    visible_keys = [k for k in parsed_data if query in k.lower()]
    display_entries(reset=True)

def load_more():
    global entries_per_page
    entries_per_page += MAX_VISIBLE_ITEMS
    display_entries()

def reset_defaults():
    if original_xml:
        build_editor_from_xml(original_xml)

def toggle_sensitive():
    global sensitive_hidden
    sensitive_hidden = not sensitive_hidden
    display_entries(reset=True)

def save_file():
    if not current_file_path:
        return show_error("No File", "Please open a save file first.")
    new_data = {}
    for key, (t, widget) in widget_refs.items():
        if t == 'bool':
            new_data[key] = '1' if widget.get() else '0'
        else:
            new_data[key] = widget.get()
    updated_xml = rebuild_xml(new_data)
    try:
        encoded = encode_save(updated_xml)
        with open(current_file_path, "wb") as f:
            f.write(encoded)
        messagebox.showinfo("Saved", "Save file updated successfully.")
    except Exception as e:
        show_error("Save Error", str(e))

def rebuild_xml(data_dict):
    root = ET.Element('plist', version="1.0")
    dict_elem = ET.SubElement(root, 'dict')
    segments = {}
    for key, val in data_dict.items():
        parts = key.split('/')
        d = segments
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        d[parts[-1]] = val
    def add_to_dict(xml_dict, source_dict):
        for k, v in source_dict.items():
            ET.SubElement(xml_dict, 'k').text = k
            if isinstance(v, dict):
                child_dict = ET.SubElement(xml_dict, 'dict')
                add_to_dict(child_dict, v)
            else:
                ET.SubElement(xml_dict, 's').text = v
    add_to_dict(dict_elem, segments)
    return ET.tostring(root, encoding='utf-8', method='xml').decode('utf-8')

def show_error(title, message):
    try:
        messagebox.showerror(title, message)
    except:
        print(f"[ERROR] {title}: {message}")

def threaded_open_file():
    def task():
        global current_file_path
        path = filedialog.askopenfilename(filetypes=[("Geometry Dash Save", "*.dat")])
        if not path:
            return
        try:
            with open(path, 'rb') as f:
                raw = f.read()
            decoded = decode_save(raw)
            current_file_path = path
            asyncio.run(async_build(decoded))
        except Exception as e:
            show_error("Open File Error", str(e))
    threading.Thread(target=task).start()

async def async_build(xml):
    await asyncio.sleep(0.01)
    build_editor_from_xml(xml)

# === Tkinter UI ===
root = tk.Tk()
root.title("GDSE")
root.geometry("900x600")

top_bar = tk.Frame(root)
top_bar.pack(fill=tk.X, pady=5)

tk.Button(top_bar, text="Open Save File", command=threaded_open_file).pack(side=tk.LEFT, padx=5)
tk.Button(top_bar, text="Save", command=save_file).pack(side=tk.LEFT, padx=5)
tk.Button(top_bar, text="Load More", command=load_more).pack(side=tk.LEFT, padx=5)
tk.Button(top_bar, text="Reset to Defaults", command=reset_defaults).pack(side=tk.LEFT, padx=5)
tk.Button(top_bar, text="Toggle Sensitive Info", command=toggle_sensitive).pack(side=tk.LEFT, padx=5)

search_var = tk.StringVar()
search_var.trace_add("write", on_search)
search_entry = tk.Entry(top_bar, textvariable=search_var)
search_entry.pack(side=tk.RIGHT, padx=10)
tk.Label(top_bar, text="Search:").pack(side=tk.RIGHT)

editor_canvas = tk.Canvas(root, bg="#f0f0f0")
editor_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(root, orient="vertical", command=editor_canvas.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

editor_canvas.configure(yscrollcommand=scrollbar.set)
scrollable_frame = tk.Frame(editor_canvas, bg="#f0f0f0")
scroll_window = editor_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

def on_configure(event):
    editor_canvas.configure(scrollregion=editor_canvas.bbox("all"))

scrollable_frame.bind("<Configure>", on_configure)

def on_mousewheel(event):
    if platform.system() == 'Windows':
        editor_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    else:
        editor_canvas.yview_scroll(int(-1 * (event.delta)), "units")

editor_canvas.bind_all("<MouseWheel>", on_mousewheel)  # Windows/macOS
editor_canvas.bind_all("<Button-4>", lambda e: editor_canvas.yview_scroll(-1, "units"))  # Linux scroll up
editor_canvas.bind_all("<Button-5>", lambda e: editor_canvas.yview_scroll(1, "units"))   # Linux scroll down

root.mainloop()
