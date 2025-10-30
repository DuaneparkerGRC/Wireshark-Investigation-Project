# Network Forensics Challenge - PCAP Artifact Recovery (Wireshark + HxD)

**Context:** This was **1 of 7 interesting, hands-on projects** I completed on an online platform.  
**Goal:** Investigate an incident from a provided **Wireshark PCAP**, isolate HTTP/TCP streams, extract **raw objects**, and rebuild files in **HxD Hex Editor**.  
**My extra prep:** I built a quick **file-signature cheat sheet** (magic bytes, common headers/footers) to speed up hunting in streams.

---

## Tools I Used
- **Wireshark** (filtering, TCP stream reconstruction)
- **HxD Hex Editor** (byte-level carving & file rebuilds)
- **Base64 decoder** (for streams that weren’t binary)
- My **file-signature cheat sheet** (JPG/PNG/PDF/DOCX/ZIP)

---

## Approach (short)
1. Open PCAP with Wirehsark → filter HTTP/interesting traffic → **Follow TCP Stream**.  **Download PCAP:** [Click here](https://github.com/DuaneparkerGRC/Wireshark-Investigation-Project/raw/de4e51e97b07c4c2494d1f442adb7311fc5b307f/Digital_Investigation%20Task%20%28pcap%20file%29%20%281%29.pcapng)
2. Identify **magic bytes** / headers & footers from TCP flow (e.g., JPEG `FF D8 … FF D9`, PDF `%PDF` → `25 50 44 46`, PNG `89 50 4E 47`, ZIP `50 4B 03 04`).  
3. **Copy raw bytes** of each object → **HxD** → save with correct extension.  
4. For odd cases: check **ASCII/Base64**, or look for **embedded/second signatures** in the same stream.


### Common file signatures (Cheat Sheet)

| Format | Hex (first bytes) | ASCII | Notes |
|---|---|---|---|
| JPEG | FF D8 FF | ... | Starts with SOI `FFD8` then marker (`FFEx`/`FFE1` etc.). Ends `FF D9`. |
| PNG | 89 50 4E 47 0D 0A 1A 0A | .PNG.... | Fixed 8-byte PNG signature. |
| GIF87a | 47 49 46 38 37 61 | GIF87a | Legacy GIF. |
| GIF89a | 47 49 46 38 39 61 | GIF89a | Common GIF. |
| BMP | 42 4D | BM | Windows bitmap. |
| TIFF (LE) | 49 49 2A 00 | II*. | Little-endian TIFF. |
| TIFF (BE) | 4D 4D 00 2A | MM.* | Big-endian TIFF. |
| ICO | 00 00 01 00 | .... | Windows icon (CUR is `00 00 02 00`). |
| WEBP | 52 49 46 46 **.. .. .. ..** 57 45 42 50 | RIFF....WEBP | RIFF container; `WEBP` at offset 8. |
| PDF | 25 50 44 46 2D | %PDF- | Header like `%PDF-1.7`. |
| ZIP | 50 4B 03 04 | PK.. | Local file header. Also `50 4B 05 06` (empty) or `50 4B 07 08`. |
| 7z | 37 7A BC AF 27 1C | 7z..'. | 7-Zip container. |
| RAR v1.5–4.x | 52 61 72 21 1A 07 00 | Rar!... | Legacy RAR. |
| RAR v5 | 52 61 72 21 1A 07 01 00 | Rar!... | New RAR5. |
| GZIP | 1F 8B 08 | ... | Deflate method = `08`. |
| BZIP2 | 42 5A 68 | BZh | Next byte is version (31–39). |
| XZ | FD 37 7A 58 5A 00 | .7zXZ. | xz stream. |
| TAR (ustar) | 75 73 74 61 72 00 | ustar. | At **offset 257**, not the start. |
| ISO 9660 | 43 44 30 30 31 | CD001 | At **offset 0x8001** (and 0x8801, 0x9001). |
| ELF | 7F 45 4C 46 | .ELF | Linux/UNIX executables. Class/endian follow. |
| Mach-O (thin) | CF FA ED FE | .... | 32-bit big-endian; other combos: `CE FA ED FE`, `FE ED FA CE/CF`. |
| Mach-O (fat) | CA FE BA BE | .... | Universal/fat binary (also `CA FE BA BF` for 64-bit header). |
| PE (EXE/DLL) | 4D 5A | MZ | DOS stub; `50 45 00 00` (“PE\0\0”) at offset from `e_lfanew`. |
| Java Class | CA FE BA BE | .... | Followed by version. |
| .NET (CLI) | 4D 5A | MZ | PE with CLI metadata; look for `BSJB`/`CLR` metadata after PE headers. |
| SQLite | 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00 | SQLite format 3\0 | Exact 16-byte header. |
| XML | 3C 3F 78 6D 6C 20 | <?xml | May begin with UTF BOM; not a strict signature. |
| HTML | 3C 21 44 4F 43 54 59 50 45 | <!DOCTYPE | Also may start with `<html` etc. |
| JSON | 7B or 5B | { or [ | No formal magic; whitespace/BOM may precede. |
| MP3 (ID3) | 49 44 33 | ID3 | If no ID3 tag, frames start `FF FB` / `FF F3` / `FF F2`. |
| AAC (ADTS) | FF F1 or FF F9 | .. | Syncword `FFF`, MPEG-2/4 profile bits set. |
| WAV | 52 49 46 46 **.. .. .. ..** 57 41 56 45 | RIFF....WAVE | RIFF container; `WAVE` at offset 8. |
| AVI | 52 49 46 46 **.. .. .. ..** 41 56 49 20 | RIFF....AVI | RIFF container; `AVI ` at offset 8. |
| MP4 / M4V / MOV | **.. .. .. ..** 66 74 79 70 | ....ftyp | `ftyp` at **offset 4**; brand e.g., `isom`, `mp42`, `qt  `. |
| MKV / WebM | 1A 45 DF A3 | .... | EBML header; DocType `matroska`/`webm` later. |
| OGG | 4F 67 67 53 | OggS | Ogg container (Vorbis/Opus/Theora, etc.). |
| FLAC | 66 4C 61 43 | fLaC | FLAC stream. |
| PNG ICO (ICNS) | 69 63 6E 73 | icns | macOS icon. |
| PSD | 38 42 50 53 | 8BPS | Adobe Photoshop. |
| RTF | 7B 5C 72 74 66 31 | {\rtf1 | Rich Text Format. |
| OLE (DOC/XLS/PPT) | D0 CF 11 E0 A1 B1 1A E1 | ....... | Compound File Binary (Office 97–2003). |
| OOXML (DOCX/XLSX/PPTX) | 50 4B 03 04 | PK.. | It’s ZIP with specific directories (`word/`, `xl/`, `ppt/`). |
| APK/IPA/JAR | 50 4B 03 04 | PK.. | ZIP containers with platform-specific structure. |

---

## Sub-Tasks & Results

### Sub-task 1
- **Prompt:** Extract `anz-logo.jpg` and `bank-card.jpg`.  
- **Method:** Isolated HTTP streams → copied bytes between **JPG header/footer** → saved via HxD.  
- **Result:** Both images successfully regenerated.

<img width="225" height="225" alt="fix1" src="https://github.com/user-attachments/assets/f53e53db-758a-41e3-b315-d06bf28b95ee" />

<img width="283" height="178" alt="fix7" src="https://github.com/user-attachments/assets/ffdb4fc2-2405-49eb-b268-09648018dead" />

### Sub-task 2
- **Prompt:** Extract `ANZ1.jpg` and `ANZ2.jpg` and note what’s different.  
- **Method:** Same carve process as Sub-task 1.  
- **Finding:** **Hidden messages appended after the image end marker** in both streams.  
  - `ANZ1.jpg`: “**You've found a hidden message in this file! Include it in your write-up.**”  
  - `ANZ2.jpg`: “**You've found the hidden message! Images are sometimes more than they appear.**”
 
<img width="175.4" height="248.2" alt="fix6" src="https://github.com/user-attachments/assets/2240a728-3b3c-4617-93e3-4c440139f5fe" />

<img width="175.4" height="248.2" alt="fix2" src="https://github.com/user-attachments/assets/f20f6bb0-0e19-4bc5-8bea-34167e32c25a" />


### Sub-task 3
- **Prompt:** Recover contents of `how-to-commit-crimes.docx`.  
- **Method:** Stream contained readable **ASCII**; did not need raw carve.  
- **Recovered text:** “**Step 1: Find target  Step 2: Hack them  This is a suspicious document**”.

- Step 1: Find target Step 2: Hack them This is a suspicious document


### Sub-task 4

- **Prompt:** Extract and view PDFs: `ANZ_Document.pdf`, `ANZ_Document2.pdf`, `evil.pdf`.  
- **Method:** Found **`%PDF` (25 50 44 46)** in streams → copied from header through EOF → saved in HxD.  
- **Result:** All three PDFs opened successfully.

[pdf3.pdf](https://github.com/user-attachments/files/23226302/pdf3.pdf)
[pdf2.pdf](https://github.com/user-attachments/files/23226301/pdf2.pdf)
[pdf1.pdf](https://github.com/user-attachments/files/23226298/pdf1.pdf)


### Sub-task 5
- **Prompt:** Find contents of `hiddenmessage2.txt`.  
- **Method:** Stream was **not plain text**; hex showed a **JPG signature**.  
- **Result:** The “TXT” was actually an **image**; carved as JPEG and recovered.

<img width="640" height="360" alt="fix3" src="https://github.com/user-attachments/assets/b5dfac2c-ff6f-43e1-b1cc-cfa4ccdbd3a8" />



### Sub-task 6
- **Prompt:** Investigate `atm-image.jpg` and explain what’s different.  
- **Method:** TCP stream contained **two JPEG signatures** (two images in one flow).  
- **Result:** Carved **two separate images** from the same stream.

<img width="275" height="183" alt="fix5" src="https://github.com/user-attachments/assets/ff183847-eaa9-4eb7-86d9-82c7391c298d" />

<img width="266" height="190" alt="fix4" src="https://github.com/user-attachments/assets/2990e4ef-b747-4728-b1fb-9c97a60956a0" />

### Sub-task 7

- **Prompt:** Extract `broken.png`.  
- **Method:** No PNG header in hex; **ASCII view showed Base64**.  
- **Result:** Decoded Base64 and saved as PNG successfully.


<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/e87411f4-2c5a-46f5-8c38-4cf340dd007c" />


### Sub-task 8
- **Prompt:** Access `securepdf.pdf` and include it; detail steps.  
- **Method:** No `%PDF`; found hint “password is **secure**” and **ZIP signatures** `50 4B 03 04` … `50 4B 05 06`.  
- **Outcome:** Attempted multiple carves; resulting ZIP was **corrupt**. Document could not be opened (documented as **inconclusive**).

---

## What I Learned
- **Signature-driven carving** is fast: a small cheatsheet of **magic bytes** dramatically speeds incident analysis.  
- **Streams can hide more than one object**: look for **second headers** after legitimate EOFs.  
- **Don’t trust file extensions**: “.txt” can be an image; **content > name**.  
- **Try multiple views**: Hex, ASCII, and Base64 decoding all mattered.  
- **Document limits clearly**: recording inconclusive outcomes (like the corrupt ZIP) is part of a credible report.

---

## Screenshots (add your images)
<!-- Screenshot 1 -->
<figure>
  <img width="1280" height="720" alt="Screenshot 2025-10-30 132151"
       src="https://github.com/user-attachments/assets/7ae0dd56-f72a-42cb-aafb-01b5c5e1161e" />
  <figcaption><em>Wireshark:</em> search for http data and TCP flow data.</figcaption>
</figure>
---
<!-- Screenshot 2 -->
<figure>
  <img width="1280" height="720" alt="Screenshot 2025-10-30 132131"
       src="https://github.com/user-attachments/assets/57d0ca79-6d17-4d8c-92b1-7e41f488f929" />
  <figcaption><em>View of Raw Data:</em> Extracting Raw Jpeg Data.</figcaption>
</figure>
---
<!-- Screenshot 3 -->
<figure>
  <img width="1280" height="720" alt="Screenshot 2025-10-30 132549"
       src="https://github.com/user-attachments/assets/63c46886-d87a-4170-a196-6a2f81621268" />
  <figcaption><em>Hxd Hex Reader:</em> Genarating image from Raw data captured.</figcaption>
</figure>
