import tkinter as tk
from tkinter import ttk, scrolledtext
import pyperclip
import summarize_ai as ai
from asksageclient import AskSageClient
import threading


#
from cisa_bulletin_summary import (
    fetch_advisory_links,
    fetch_advisory_text,
    extract_iocs,
    dict_to_text
    )


def format_report(report):
    return f'''
--------------------------------------------------------------------------------------------
CISA Bulletin: {report["title"]}
--------------------------------------------------------------------------------------------
Summary:
{report["summary"]}


________________________
IOCs To Be Blocked:
{report["iocs"]}
________________________
'''.strip()




def threaded_report_generation(status_label, update_callback):
    def worker():
        reports = []
        credentials = ai.load_credentials('creds.json')
        api_key = credentials['credentials']['api_key']
        email = credentials['credentials']['Ask_sage_user_info']['username']
        ask_sage_client = AskSageClient(email, api_key)

        bulletins = fetch_advisory_links(
            "https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94"
        )

        total = len(bulletins[:5])
        for idx, bulletin in enumerate(bulletins[:5]):
            ioc_data = fetch_advisory_text(bulletin[1]['url'])
            title = bulletin[1]['title']
            text = ioc_data[1]

            summary = ai.summarize(text, ask_sage_client)

            if ioc_data[0] != 'No IOCs':
                cisa_json = [j for j in ioc_data[0].json()['objects'] if j['type'] == 'indicator']
                cisa_iocs = [item['pattern'] for item in cisa_json]
                iocs = extract_iocs(cisa_iocs)
                pretty_iocs = dict_to_text(iocs)
            else:
                pretty_iocs = 'No IOCs'

            report = {
                "title": title,
                "summary": summary,
                "iocs": pretty_iocs
            }
            reports.append(report)

            # UI callback with updated reports
            update_callback(reports)
            status_label.config(text=f"Fetched {len(reports)} of {total} reports")

    threading.Thread(target=worker, daemon=True).start()

def launch_ui(_):
    reports = []
    current_index = 0

    def update_display():
        if not reports:
            return
        report = reports[current_index]
        title_label.config(text=report["title"])
        text_area.configure(state='normal')
        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, format_report(report))
        text_area.configure(state='disabled')
        prev_btn["state"] = tk.NORMAL if current_index > 0 else tk.DISABLED
        next_btn["state"] = tk.NORMAL if current_index < len(reports) - 1 else tk.DISABLED

    def update_reports(new_reports):
        nonlocal reports, current_index
        reports = new_reports
        current_index = len(reports) - 1
        update_display()

    def prev_report():
        nonlocal current_index
        if current_index > 0:
            current_index -= 1
            update_display()

    def next_report():
        nonlocal current_index
        if current_index < len(reports) - 1:
            current_index += 1
            update_display()

    def copy_to_clipboard():
        pyperclip.copy(text_area.get("1.0", tk.END).strip())

    root = tk.Tk()
    root.title("CISA Bulletin Viewer")
    root.geometry("900x600")
    root.configure(bg="#1E1E1E")

    font_title = ("Segoe UI", 14, "bold")
    font_text = ("Consolas", 11)
    fg_color = "#00FFBA"
    bg_color = "#1E1E1E"

    title_label = tk.Label(root, text="", font=font_title, bg=bg_color, fg=fg_color)
    title_label.pack(pady=(20, 10))

    text_area = scrolledtext.ScrolledText(
        root, wrap=tk.WORD, font=font_text,
        bg="#2D2D2D", fg="#DCDCDC", insertbackground="white"
    )
    text_area.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

    nav_frame = tk.Frame(root, bg=bg_color)
    nav_frame.pack(pady=5)

    prev_btn = ttk.Button(nav_frame, text="Previous", command=prev_report)
    prev_btn.grid(row=0, column=0, padx=5)

    copy_btn = ttk.Button(nav_frame, text="Copy to Clipboard", command=copy_to_clipboard)
    copy_btn.grid(row=0, column=1, padx=5)

    next_btn = ttk.Button(nav_frame, text="Next", command=next_report)
    next_btn.grid(row=0, column=2, padx=5)

    status_label = tk.Label(root, text="Fetching reports...", font=("Segoe UI", 10), bg=bg_color, fg="white")
    status_label.pack(pady=(5, 10))

    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TButton", background="#00FFBA", foreground="black", font=("Segoe UI", 10, "bold"))
    style.map("TButton", background=[("active", "#00CCA0")])

    # Start background fetch
    threaded_report_generation(status_label, update_reports)

    root.mainloop()

if __name__ == "__main__":
        launch_ui([])  # Start with empty report list, populate live
