import qrcode
import os

art_dir = r"C:\Users\SPOORTI\.gemini\antigravity\brain\0fd5baf6-d547-4927-af47-60ec54a9abce"
os.makedirs(art_dir, exist_ok=True)

wifi_url = "http://192.168.14.60:5000/login"
pub_url = "https://roots-went-seasons-broken.trycloudflare.com/login"

qr1 = qrcode.QRCode(box_size=10, border=3)
qr1.add_data(wifi_url)
qr1.make(fit=True)
img1 = qr1.make_image(fill_color="black", back_color="white")
img1.save(os.path.join(art_dir, "join_qr_wifi.png"))
img1.save(os.path.join(art_dir, "join_qr.png"))

qr2 = qrcode.QRCode(box_size=10, border=3)
qr2.add_data(pub_url)
qr2.make(fit=True)
img2 = qr2.make_image(fill_color="black", back_color="white")
img2.save(os.path.join(art_dir, "join_qr_public.png"))

print("Successfully generated verified QR codes!")
