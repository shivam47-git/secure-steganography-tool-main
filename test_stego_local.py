from PIL import Image
import sys
import os
# Ensure project directory is in sys.path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from steganography import encode_image, decode_image

def main():
    img_path = r"C:\Users\grdsh\Desktop\BUG_HAVEN\watermarking\secure-steganography-tool-main\assets\demo_images\landscape.png"
    img = Image.open(img_path)
    msg = "Hello from Antigravity"
    stego = encode_image(img, msg)
    print("Encoded image size:", stego.size)
    decoded = decode_image(stego)
    print("Decoded message:", decoded)

if __name__ == "__main__":
    main()
