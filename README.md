# GIFXploit — Ultimate GIF Forensics & CTF Tool

Extract GCT/LCT, visualize palettes, multi-frame LSB/OCR/XOR decoding, and automatic flag detection.

**Developed by Shoaib Bin Rashid (R3D_XplOiT)**

## Quick start

```bash
# clone
git clone https://github.com/<your-github-username>/gifxploit.git
cd gifxploit

# create virtualenv (optional)
python3 -m venv venv
source venv/bin/activate

# install dependencies
pip3 install -r requirements.txt

# run (auto everything)
python3 gifxploit.py challenge.gif

# or with a flag regex
python3 gifxploit.py challenge.gif "FLAG\{.*?\}"
