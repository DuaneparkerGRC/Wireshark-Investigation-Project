# Network Forensics Challenge — PCAP Artifact Recovery (Wireshark + HxD)

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
1. Open PCAP → filter HTTP/interesting traffic → **Follow TCP Stream**.  
2. Identify **magic bytes** / headers & footers (e.g., JPEG `FF D8 … FF D9`, PDF `%PDF` → `25 50 44 46`, PNG `89 50 4E 47`, ZIP `50 4B 03 04`).  
3. **Copy raw bytes** of each object → **HxD** → save with correct extension.  
4. For odd cases: check **ASCII/Base64**, or look for **embedded/second signatures** in the same stream.

---

## Sub-Tasks & Results

### Sub-task 1
- **Prompt:** Extract `anz-logo.jpg` and `bank-card.jpg`.  
- **Method:** Isolated HTTP streams → copied bytes between **JPG header/footer** → saved via HxD.  
- **Result:** Both images successfully regenerated.

### Sub-task 2
- **Prompt:** Extract `ANZ1.jpg` and `ANZ2.jpg` and note what’s different.  
- **Method:** Same carve process as Sub-task 1.  
- **Finding:** **Hidden messages appended after the image end marker** in both streams.  
  - `ANZ1.jpg`: “**You've found a hidden message in this file! Include it in your write-up.**”  
  - `ANZ2.jpg`: “**You've found the hidden message! Images are sometimes more than they appear.**”

### Sub-task 3
- **Prompt:** Recover contents of `how-to-commit-crimes.docx`.  
- **Method:** Stream contained readable **ASCII**; did not need raw carve.  
- **Recovered text:** “**Step 1: Find target  Step 2: Hack them  This is a suspicious document**”.

### Sub-task 4
- **Prompt:** Extract and view PDFs: `ANZ_Document.pdf`, `ANZ_Document2.pdf`, `evil.pdf`.  
- **Method:** Found **`%PDF` (25 50 44 46)** in streams → copied from header through EOF → saved in HxD.  
- **Result:** All three PDFs opened successfully.

### Sub-task 5
- **Prompt:** Find contents of `hiddenmessage2.txt`.  
- **Method:** Stream was **not plain text**; hex showed a **JPG signature**.  
- **Result:** The “TXT” was actually an **image**; carved as JPEG and recovered.

### Sub-task 6
- **Prompt:** Investigate `atm-image.jpg` and explain what’s different.  
- **Method:** TCP stream contained **two JPEG signatures** (two images in one flow).  
- **Result:** Carved **two separate images** from the same stream.

### Sub-task 7
- **Prompt:** Extract `broken.png`.  
- **Method:** No PNG header in hex; **ASCII view showed Base64**.  
- **Result:** Decoded Base64 and saved as PNG successfully.

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
> Replace the placeholders with your own captures.

- ![Wireshark filtering & TCP Stream](screenshots/wireshark_stream.png)  
- ![HxD carving a JPEG between FF D8 … FF D9](screenshots/hxd_carve_jpg.png)  
- ![Recovered images & PDFs](screenshots/recovered_artifacts.png)

---
