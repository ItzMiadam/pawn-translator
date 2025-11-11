import re
import json
import time
import urllib.request
from deep_translator import GoogleTranslator
from tqdm import tqdm
import os
import html

INPUT_FILE = "publics.pwn"
OUTPUT_FILE = "lrp_translated.pwn"
CACHE_FILE = "translation_cache.json"
FAILED_LOG = "failed_translations.txt"
BATCH_SIZE = 20
USE_LIMIT = True
TRANSLATION_LIMIT = 5000

def load_json_file(filepath, default_data={}):
    try:
        if not os.path.exists(filepath):
            return default_data
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"Warning: Cache file '{filepath}' not found or corrupted. Starting with empty cache.")
        return default_data

def save_json_file(filepath, data):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def contains_russian(text):
    return re.search(r'[а-яА-ЯёЁ]', text) is not None

def is_internet_connected(url="http://www.google.com", timeout=3):
    try:
        urllib.request.urlopen(url, timeout=timeout)
        return True
    except Exception:
        return False

def wait_for_internet(check_interval=5):
    print("Waiting for internet connection...")
    while not is_internet_connected():
        time.sleep(check_interval)
    print("✅ Internet connected. Resuming...")

def translate_single_text(text, pbar):
    if not text or not text.strip():
        return text

    max_retries = 5
    retry_delay = 3
    for attempt in range(max_retries):
        try:
            translator = GoogleTranslator(source='ru', target='en')
            translated_text = translator.translate(text)

            # Clean up potential HTML entities from the result
            if translated_text:
                translated_text = html.unescape(translated_text)
            else:
                translated_text = text

            return translated_text

        except Exception as e:
            pbar.write(f"\nTranslation error for '{text[:30]}...': {e} | Retrying {attempt + 1}/{max_retries}")
            if any(err in str(e) for err in ["Failed to establish a new connection", "Name or service not known"]):
                wait_for_internet()
            else:
                time.sleep(retry_delay)

    pbar.write(f"\n❌ Failed to translate '{text[:30]}...' after {max_retries} attempts.")
    with open(FAILED_LOG, "a", encoding="utf-8") as f:
        f.write(text + "\n")
    return text 

def process_strings_semantically(all_strings_raw, cache, pbar_main):

    code_pattern = re.compile(
        r"(\{[\w#]+\})"              # (1) {COLOR} codes
        r"|(\%[-.\d]*[sdifucU\%])"  # (2) Format specifiers (%s, %d)
        r"|(\\[ntbrfva\"'\\{} ])"    # (3) Pawn escape sequences (\n, \t, \\)
        r"|(\\\r?\n)"                # (4) C-style line continuation
        r"|(\s{2,})"                 # (5) Multiple spaces
        r"|(\r)"                     # (6) Standalone carriage return
        r"|(\n)"                     # (7) Standalone newline
    )

    strings_to_translate_map = {}

    # 2. Parse strings to extract text fragments
    for raw_string in all_strings_raw:
        # Only process strings not already in cache that contain Russian characters
        if raw_string not in cache and contains_russian(raw_string):
            tokens = code_pattern.split(raw_string)
            valid_tokens = [t for t in tokens if t is not None and t != '']

            text_fragments = [t for t in valid_tokens if not code_pattern.fullmatch(t) and contains_russian(t)]

            if text_fragments:
                strings_to_translate_map[raw_string] = text_fragments

    unique_texts_to_translate = list(dict.fromkeys([item for sublist in strings_to_translate_map.values() for item in sublist]))

    if not unique_texts_to_translate:
        pbar_main.write("No new Russian texts found to translate in this batch.")
        return cache, 0 # Return cache and 0 new translations

    pbar_main.write(f"Found {len(unique_texts_to_translate)} unique text fragments to translate in this batch.")

    # 4. Translate fragments
    translation_map = {}
    new_translations_count = 0
    with tqdm(total=len(unique_texts_to_translate), desc="Translating fragments", unit="frag") as pbar_translate:
        for text in unique_texts_to_translate:
            translated_text = translate_single_text(text, pbar_translate)
            translation_map[text] = translated_text
            new_translations_count += 1
            pbar_translate.update(1)

    # 5. Reconstruct the original strings and apply AI cleanup
    for raw_string in strings_to_translate_map.keys():
        reconstructed_string = ""
        tokens = [t for t in code_pattern.split(raw_string) if t is not None and t != '']

        for token in tokens:
            reconstructed_string += translation_map.get(token, token)

        reconstructed_string = re.sub(r'\\?\s*\r?\n\s*', ' ', reconstructed_string)
        
        reconstructed_string = re.sub(r' +\n', r'\n', reconstructed_string)

        # --- Post-processing after reconstruction ---
        reconstructed_string = re.sub(r'([a-zA-Zа-яА-ЯёЁ])(%[-.\d]*[sdifucU%])', r'\1 \2', reconstructed_string)
        reconstructed_string = re.sub(r'(%[-.\d]*[sdifucU%])([a-zA-Zа-яА-ЯёЁ])', r'\1 \2', reconstructed_string)

        cache[raw_string] = reconstructed_string
        pbar_main.update(1)

    return cache, new_translations_count


def generate_output_file(original_content, cache, pattern_obj, output_filepath):
    def replace_from_cache(match):
        if match.group(2) is not None: # It's a string literal
            original_string_content = match.group(2)
            translated_content = cache.get(original_string_content)

            if translated_content is not None:
                escaped_for_pawn = ""
                i = 0
                while i < len(translated_content):
                    char = translated_content[i]
                    if char == '\\':
                        # Check if it's an existing Pawn escape sequence or a literal backslash that needs escaping.
                        # This list should cover all valid single-backslash escapes in Pawn.
                        if i + 1 < len(translated_content) and translated_content[i+1] in ['n', 't', 'b', 'r', 'f', 'v', 'a', '"', '\'', '\\', '%', '{', '}',' ']:
                            # It's an already correct Pawn escape sequence, keep it as is.
                            # The regex in process_strings_semantically should ensure these are treated as single tokens.
                            # If the translator returns something like "text\nmore", we should keep it.
                            escaped_for_pawn += char + translated_content[i+1]
                            i += 1 # Skip the next char as it's part of the escape
                        else:
                            # It's a literal backslash not part of a recognized escape, needs to be \\
                            # Example: If translated_content has "C:\path", this '\' needs to be '\\'
                            # Or if original text had a literal '\' that wasn't a Pawn escape, and the translator kept it.
                            escaped_for_pawn += '\\\\'
                    elif char == '"':
                        # Literal double quote, always needs to be \"
                        escaped_for_pawn += '\\"'
                    else:
                        # Regular character, add as is
                        escaped_for_pawn += char
                    i += 1

                return f'"{escaped_for_pawn}"'
            else:
                return match.group(1)

        return match.group(0)

    translated_content = pattern_obj.sub(replace_from_cache, original_content)
    with open(output_filepath, "w", encoding="cp1251", errors='replace') as f:
        f.write(translated_content)

if __name__ == "__main__":
    try:
        string_or_comment_pattern = re.compile(
            r'("((?:\\.|[^"\\])*?)")' # Captures string literals, group 2 is the content inside quotes
            r'|(/\*.*?\*/)'           # Captures block comments
            r'|(//[^\r\n]*)',          # Captures line comments
            re.DOTALL
        )
        print(f"📦 Creating backup of input file: {INPUT_FILE}.bak")
        try:
            with open(INPUT_FILE, "r", encoding="cp1251", errors='replace') as f_in, \
                 open(INPUT_FILE + ".bak", "w", encoding="cp1251", errors='replace') as f_out:
                f_out.write(f_in.read())
        except Exception as e:
            print(f"Warning: Could not create backup file. {e}")

        print(f"Reading input file: {INPUT_FILE}")
        with open(INPUT_FILE, "r", encoding="cp1251", errors='replace') as f:
            original_content = f.read()

        translation_cache = load_json_file(CACHE_FILE)

        print("Extracting all string literals...")
        all_strings_raw = [match.group(2) for match in string_or_comment_pattern.finditer(original_content) if match.group(2) is not None]
        unique_raw_strings = list(dict.fromkeys(all_strings_raw))

        strings_needing_translation = [s for s in unique_raw_strings if s not in translation_cache and contains_russian(s)]

        print(f"Total unique strings: {len(unique_raw_strings)}")
        print(f"Number of cached translations: {len(translation_cache)}")
        print(f"Number of new strings to process: {len(strings_needing_translation)}")

        if not strings_needing_translation:
            print("All strings have already been translated. Generating final output file...")
            generate_output_file(original_content, translation_cache, string_or_comment_pattern, OUTPUT_FILE) # Generate final output
        else:
            if USE_LIMIT:
                strings_needing_translation = strings_needing_translation[:TRANSLATION_LIMIT]
                print(f"Translation limit applied: Only {len(strings_needing_translation)} strings will be processed.")

            total_strings_to_process = len(strings_needing_translation)
            

            translated_in_current_session_count = 0
            
            for i in range(0, total_strings_to_process, 1): 
                current_string = strings_needing_translation[i]

                if current_string not in translation_cache:
                    print(f"\n--- Processing string {i + 1}/{total_strings_to_process} ---")
                    
                    with tqdm(total=1, desc="Processing string", unit="string") as pbar:
                        translation_cache, new_translations_in_batch = process_strings_semantically([current_string], translation_cache, pbar)
                    
                    translated_in_current_session_count += new_translations_in_batch

                    if translated_in_current_session_count >= BATCH_SIZE:
                        print(f"\n{translated_in_current_session_count} new translations achieved. Saving updated cache to disk...")
                        save_json_file(CACHE_FILE, translation_cache)

                        print(f"\nGenerating output file with current translations...")
                        generate_output_file(original_content, translation_cache, string_or_comment_pattern, OUTPUT_FILE)
                        translated_in_current_session_count = 0


            # After the loop, save any remaining translations that didn't form a full batch
            if translated_in_current_session_count > 0:
                print(f"\nSaving final {translated_in_current_session_count} remaining translations to disk...")
                save_json_file(CACHE_FILE, translation_cache)
                print(f"\nGenerating final output file with all translations...")
                generate_output_file(original_content, translation_cache, string_or_comment_pattern, OUTPUT_FILE)


        print(f"\nProcess completed successfully. The final file is located at:")
        print(f"File path: {OUTPUT_FILE}")
        if os.path.exists(FAILED_LOG) and os.path.getsize(FAILED_LOG) > 0:
            print(f"Some translations failed. Their list is in: {FAILED_LOG}")

    except Exception as e:
        import traceback
        print(f"\n❌ An unexpected general error occurred in the program: {e}")
        traceback.print_exc()