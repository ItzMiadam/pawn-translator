# Pawn Russian-to-English Translator

A Python script to translate Russian text strings in Pawn (`.pwn`) files into English using Google Translate.

---

## Features

- Supports **Pawn files** with **cp1251 encoding**.
- Smart translation of strings while preserving **Pawn formatting codes** (`{COLOR}`, `%d`, `\n`, etc.).
- Translation caching in **JSON** to avoid redundant translations.
- Error handling and retry mechanism for internet connectivity issues.
- Logs failed translations in `failed_translations.txt`.


---

## Requirements
- Note that this script has only been tested on Russian files!
- Python 3.12.5 (tested)
- To translate your desired file, set the INPUT_FILE variable to the name of your file.
- Install required packages:

```bash
pip install deep-translator tqdm
