import tkinter as tk
from tkinter import filedialog
import json
import sys

def main():
    try:
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        folder_path = filedialog.askdirectory(title="Select Directory")
        if folder_path:
            output = {"folder_path": folder_path}
        else:
            output = {"error": "No directory selected"}
        print(json.dumps(output))
    except Exception as e:
        output = {"error": str(e)}
        print(json.dumps(output), file=sys.stderr)

if __name__ == "__main__":
    main()