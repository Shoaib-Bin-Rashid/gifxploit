#!/usr/bin/env python3
"""
GIFXploit - Ultimate All-in-One GIF forensic & CTF tool

Developed by Shoaib Bin Rashid (R3D_XplOiT)
GitHub: https://github.com/<your-github-username>/gifxploit
License: MIT

Usage:
    python3 gifxploit.py challenge.gif
    python3 gifxploit.py challenge.gif "FLAG{.*?}"

What it does (automatic single-run):
 - Extract Global Color Table (GCT) -> out_gifxploit/gct.txt
 - Extract Local Color Tables (LCT) -> out_gifxploit/LCT.txt
 - Visualize 256-color palettes -> out_gifxploit/extracted_palettes/
 - Extract frames -> out_gifxploit/frames/
 - Multi-frame LSB hidden data extraction and merging -> out_gifxploit/lsb_payload.bin
 - Auto XOR decoding (common keys) + ASCII/hex attempts
 - OCR on frames (if tesseract available)
 - Auto search for optional regex pattern (flag)
"""

import os
import sys
import struct
from PIL import Image, ImageSequence
import pytesseract
import re
import itertools

COMMON_XOR_KEYS = [b'\x00', b'\xFF', b'\x42', b'\x69', b'\x20']  # add more if needed

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def read_global_color_table(fp, out_txt):
    fp.seek(0)
    header = fp.read(6)
    if not header.startswith(b'GIF'):
        raise ValueError("Not a GIF")
    width, height = struct.unpack("<HH", fp.read(4))
    packed = fp.read(1)
    if not packed:
        return []
    packed = packed[0]
    fp.read(2)  # bg idx + pixel aspect
    gct_flag = (packed & 0x80) >> 7
    colors = []
    if gct_flag:
        gct_size = 2 ** ((packed & 0x07)+1)
        raw = fp.read(3*gct_size)
        colors = [tuple(raw[i:i+3]) for i in range(0, len(raw), 3)]
        with open(out_txt, "w") as f:
            f.write(f"GCT ({len(colors)} colors)\n")
            for i,c in enumerate(colors):
                f.write(f"{i:03d}: {c}\n")
    return colors

def skip_subblocks(fp):
    while True:
        b = fp.read(1)
        if not b or b[0]==0:
            break
        fp.read(b[0])

def extract_lcts(file_path, out_txt):
    lct_list = []
    with open(file_path,"rb") as f, open(out_txt,"w") as log:
        f.read(6)
        f.read(4)
        packed_b = f.read(1)
        if not packed_b: return lct_list
        packed = packed_b[0]
        gct_flag = (packed & 0x80)>>7
        gct_size_val = packed & 0x07
        f.read(2)
        if gct_flag:
            f.read(3*(2**(gct_size_val+1)))
        frame=0
        while True:
            b = f.read(1)
            if not b: break
            if b==b'\x2C':  # Image Descriptor
                f.read(8)
                packed_field = f.read(1)
                if not packed_field: break
                pf = packed_field[0]
                lct_flag = (pf & 0x80)>>7
                lct_size_val = pf & 0x07
                if lct_flag:
                    raw=f.read(3*(2**(lct_size_val+1)))
                    colors=[tuple(raw[i:i+3]) for i in range(0,len(raw),3)]
                    lct_list.append(colors)
                    log.write(f"Frame {frame} LCT ({len(colors)} colors) first20: {colors[:20]}\n")
                else:
                    log.write(f"Frame {frame} uses GCT\n")
                f.read(1)  # LZW min code size
                skip_subblocks(f)
                frame+=1
            elif b==b'\x21':
                f.read(1)
                skip_subblocks(f)
            elif b==b'\x3B':
                log.write("GIF Trailer\n")
                break
            else:
                break
    return lct_list

def visualize_256_palettes(palettes,out_dir,block=20):
    path=os.path.join(out_dir,"extracted_palettes")
    ensure_dir(path)
    count=0
    for pal in palettes:
        if len(pal)!=256: continue
        img=Image.new("RGB",(16*block,16*block))
        for i,c in enumerate(pal):
            r,g,b=c
            row,col=i//16,i%16
            for x in range(block):
                for y in range(block):
                    img.putpixel((col*block+x,row*block+y),(r,g,b))
        img.save(os.path.join(path,f"char_{count:03d}.png"))
        count+=1
    return count,path

def extract_frames(gif_path,out_dir):
    try:
        im=Image.open(gif_path)
    except:
        return 0
    ensure_dir(out_dir)
    count=0
    for i,frame in enumerate(ImageSequence.Iterator(im)):
        frame.convert("RGBA").save(os.path.join(out_dir,f"frame_{i:03d}.png"))
        count+=1
    return count

def lsb_extract_frames(frame_dir):
    files=sorted([os.path.join(frame_dir,f) for f in os.listdir(frame_dir) if f.lower().endswith(".png")])
    bits=[]
    for file in files:
        img=Image.open(file)
        for px in img.getdata():
            for ch in px[:3]:
                bits.append(ch&1)
    bytelist=[]
    for i in range(0,len(bits),8):
        byte=0
        for b in bits[i:i+8]:
            byte=(byte<<1)|b
        bytelist.append(byte)
    return bytes(bytelist)

def try_xor(data):
    results=[]
    for key in COMMON_XOR_KEYS:
        res=bytes([b^key[0] for b in data])
        results.append(res)
    return results

def auto_decode(data):
    candidates=[data]+try_xor(data)
    decoded=[]
    for c in candidates:
        try:
            decoded.append(c.decode())
        except:
            pass
    return decoded

def ocr_frames(frame_dir):
    texts=[]
    for f in os.listdir(frame_dir):
        if not f.lower().endswith(".png"): continue
        img=Image.open(os.path.join(frame_dir,f))
        txt=pytesseract.image_to_string(img)
        if txt.strip(): texts.append(txt.strip())
    return "\n".join(texts)

def search_flag(decoded_texts,flag_pattern):
    if not flag_pattern: return []
    flags=[]
    pattern=re.compile(flag_pattern)
    for t in decoded_texts.split("\n"):
        m=pattern.search(t)
        if m: flags.append(m.group(0))
    return flags

def main():
    if len(sys.argv)<2:
        print("Usage: python3 gifxploit.py challenge.gif [FLAG_REGEX]")
        sys.exit(1)
    gif_file=sys.argv[1]
    flag_pattern=sys.argv[2] if len(sys.argv)>2 else None
    out_base="out_gifxploit"
    ensure_dir(out_base)
    gct_txt=os.path.join(out_base,"gct.txt")
    lct_txt=os.path.join(out_base,"LCT.txt")
    frame_dir=os.path.join(out_base,"frames")

    print(f"[+] Processing {gif_file}")
    # GCT
    try:
        with open(gif_file,"rb") as fh:
            gct=read_global_color_table(fh,gct_txt)
        print(f"[+] GCT extracted {len(gct)} colors -> {gct_txt}")
    except Exception as e:
        print(f"[!] GCT failed: {e}")
    # LCT
    lct_pal=extract_lcts(gif_file,lct_txt)
    print(f"[+] LCT extracted {len(lct_pal)} palettes -> {lct_txt}")
    # 256 palette visualization
    pal256=[p for p in lct_pal if len(p)==256]
    if pal256:
        cnt,path=visualize_256_palettes(pal256,out_base)
        print(f"[+] {cnt} 256-color palettes visualized -> {path}")
    # Frames
    fcount=extract_frames(gif_file,frame_dir)
    print(f"[+] {fcount} frames extracted -> {frame_dir}")
    # LSB extraction + auto decode
    lsb_data=lsb_extract_frames(frame_dir)
    decoded_texts="\n".join(auto_decode(lsb_data))
    # OCR
    ocr_text=ocr_frames(frame_dir)
    if ocr_text.strip():
        decoded_texts+="\n"+ocr_text
    # Flag search
    if flag_pattern:
        flags=search_flag(decoded_texts,flag_pattern)
        print(f"[+] Flags found: {flags}")
    else:
        print("[+] Auto decoded content:\n")
        print(decoded_texts[:1000])
    print("[DONE] All automatic analysis completed.")

if __name__=="__main__":
    main()
