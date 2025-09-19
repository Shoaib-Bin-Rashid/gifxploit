# GIFXploit — Ultimate GIF Forensics & CTF Tool

Extract GCT/LCT palettes, visualize palettes, extract frames, perform multi-frame LSB extraction/merge, try XOR/hex/ASCII decodes, run OCR on frames, and automatically search for flags.

**Developed by Shoaib Bin Rashid (R3D\_XplOiT)**

---

## Features (one-liner)

* Global Color Table (GCT) extraction
* Local Color Table (LCT) extraction (per-frame)
* Visualize 256-color palettes as 16×16 tiles
* Extract frames (PNG) from GIFs
* Multi-frame LSB extraction and merge → binary payload
* Automatic decoding attempts: ASCII, hex, common XOR, optional brute-force XOR
* OCR (pytesseract) on frames for image-to-text extraction
* Automatic flag search (defaults to common CTF patterns; accepts custom regex)
* Single-command, fully automatic workflow

---

## Quick start

```bash
# clone
git clone https://github.com/<your-github-username>/gifxploit.git
cd gifxploit

# (optional) create virtualenv
python3 -m venv venv
source venv/bin/activate

# install dependencies
pip3 install -r requirements.txt

# run (fully automatic)
python3 gifxploit.py challenge.gif

# run with custom flag regex (optional)
python3 gifxploit.py challenge.gif "FLAG\{.*?\}"
```

If you add an alias in your shell config (see below), you can run:

```bash
gifxploit challenge.gif
```

---

## Output (default folder: `out_gifxploit/`)

* `gct.txt` — Global Color Table (if present)
* `LCT.txt` — Local Color Table log (per-frame)
* `extracted_palettes/` — 16×16 visual tiles created from 256-color palettes (`char_000.png`, ...)
* `frames/` — extracted frames as `frame_000.png`, `frame_001.png`, ...
* `lsb_payload.bin` — merged LSB payload extracted from all frames
* `decoded_texts.txt` — combined auto-decoded outputs (XOR/ASCII/OCR)
* `flags_found.txt` — detected flags (if any)

---

## CLI / Usage examples

* Basic (auto everything):

  ```bash
  python3 gifxploit.py file.gif
  ```

* With custom flag regex:

  ```bash
  python3 gifxploit.py file.gif "CTF\{.*?\}"
  ```

* If you set an alias (example):

  ```bash
  # add to ~/.bashrc or ~/.zshrc
  alias gifxploit='python3 ~/path/to/gifxploit/gifxploit.py'
  source ~/.bashrc

  # then:
  gifxploit file.gif
  ```

---

## Requirements

* Python 3.8+

* Python packages:

  ```bash
  pip3 install -r requirements.txt
  ```

  `requirements.txt` includes:

  ```
  Pillow>=9.0.0
  pytesseract>=0.3.10
  ```

* For OCR (optional): system `tesseract` binary must be installed (Linux example):

  ```bash
  sudo apt update && sudo apt install -y tesseract-ocr
  ```

If `pytesseract` or the `tesseract` binary is not available, the tool will skip OCR and continue other analysis.

---

## How it helps in CTFs (quick mapping)

* **Palette tricks**: flags hidden in local/global color tables → visualize `extracted_palettes/`.
* **LSB steg**: hidden bytes across frames → `lsb_payload.bin` (run `strings`, check or decode).
* **Frame differences**: extract frames and visually inspect/order them — sometimes glyphs appear across frames.
* **OCR**: extracts readable text from palette-images or frames.
* **Auto-decode**: tries common XOR keys and ASCII/hex to save time.
* **Auto flag search**: searches for `CTF{}`, `FLAG{}` and other common regex patterns.

---

## Tips / Troubleshooting

* If OCR returns nothing: ensure the `tesseract` binary is installed and accessible in `PATH`.
* If no flags found automatically: manually inspect `extracted_palettes/` (open images in filename order), run `strings` on `lsb_payload.bin`, or enable brute-force XOR in the script.
* For very large GIFs: extraction can produce many frames; check disk space and examine frames selectively.

---

## Contributing

Contributions, issues and feature requests are welcome! Please follow these steps:

1. Fork the repo and create a branch: `feature/awesome`
2. Add your change and tests (if applicable)
3. Open a Pull Request with a short description

See `CONTRIBUTING.md` for more.

---

## Example quick workflow for a suspicious GIF

1. Run: `python3 gifxploit.py suspicious.gif`
2. Open `out_gifxploit/extracted_palettes/` → view images `char_000.png`, `char_001.png` ... in order.
3. If `lsb_payload.bin` exists: `strings out_gifxploit/lsb_payload.bin | less` or try: `xxd -p out_gifxploit/lsb_payload.bin | xxd -r -p > payload.bin` then analyze.
4. Check `out_gifxploit/decoded_texts.txt` and `out_gifxploit/flags_found.txt`.
5. If nothing, try manual XOR brute-force or visually inspect frames.

---

## 👨‍💻 Contact

Developed by **Shoaib Bin Rashid (R3D_XplOiT)**

- **LinkedIn:** [Shoaib Bin Rashid](https://www.linkedin.com/in/shoaib-bin-rashid/)
- **Email:** shoaibbinrashid11@gmail.com
- **GitHub:** [Shoaib Bin Rashid](https://github.com/Shoaib-Bin-Rashid)
- **Twitter:** [@ShoaibBinRashi1](https://x.com/ShoaibBinRashi1)

## 📄 License

MIT License © 2025 Shoaib Bin Rashid (R3D_XplOiT)
