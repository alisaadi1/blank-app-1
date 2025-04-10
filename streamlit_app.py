import streamlit as st
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import streamlit.components.v1 as components

# قائمة المستخدمين وكلمات المرور (أمثلة بسيطة)
users = {
    "kyan": "kyan91",
    "salh": "nathore8",
    "jalawi": "janah1",
    "osama": "aboloes9",
    "alasami": "qamar2",
    "abokadhim": "khadim1",
    "1": "11",
    "ali": "ali123"
}

st.set_page_config(page_title="تشفير عسكري متعدد الطبقات", layout="centered")

st.markdown("""
    <style>
    body, .stApp {
        background-color: #1e1e1e;
        color: white;
        font-family: 'Courier New', monospace;
    }
    .stTextInput>div>div>input {
        background-color: #111111;
        color: white;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🔐 تشفير عسكري متعدد الطبقات")

# ===== تسجيل الدخول =====
def login():
    st.sidebar.title("تسجيل الدخول")
    username = st.sidebar.text_input("اسم المستخدم:")
    password = st.sidebar.text_input("كلمة المرور:", type="password")
    if st.sidebar.button("تسجيل الدخول"):
        if users.get(username) == password:
            st.session_state.logged_in = True
            st.sidebar.success("✅ تم تسجيل الدخول بنجاح!")
        else:
            st.sidebar.error("❌ اسم المستخدم أو كلمة المرور غير صحيحة.")

if 'logged_in' not in st.session_state or not st.session_state.logged_in:
    login()
    st.stop()

# ===== التشفير AES =====
def generate_aes_key():
    return get_random_bytes(32)

def encrypt_aes(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return iv, ct

def decrypt_aes(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=base64.b64decode(iv))
    pt = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return pt.decode()

# ===== التشفير RSA =====
def encrypt_rsa(key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    enc_key = cipher_rsa.encrypt(key)
    return base64.b64encode(enc_key).decode()

def decrypt_rsa(encrypted_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    dec_key = cipher_rsa.decrypt(base64.b64decode(encrypted_key))
    return dec_key

# ===== التشفير المعقد =====
def complex_encrypt(message):
    key_aes = generate_aes_key()
    iv, encrypted_message = encrypt_aes(message, key_aes)

    rsa_key = RSA.generate(2048)
    private_key = rsa_key.export_key().decode()
    public_key = rsa_key.publickey().export_key()

    encrypted_key = encrypt_rsa(key_aes, public_key)
    return f"{encrypted_key}|{iv}|{encrypted_message}|{private_key}"

def complex_decrypt(encrypted_data, private_key):
    try:
        parts = encrypted_data.split('|')
        if len(parts) != 4:
            st.error("❌ النص المشفر غير صالح")
        encrypted_key, iv, encrypted_message, provided_private_key = parts
        if private_key:
            private_key = provided_private_key
        key_aes = decrypt_rsa(encrypted_key, private_key)
        decrypted_message = decrypt_aes(encrypted_message, key_aes, iv)
        return decrypted_message
    except Exception as e:
        st.error(f"❌ خطأ أثناء فك التشفير: {str(e)}")

# ===== الواجهة =====
tab1, tab2 = st.tabs(["🔐 تشفير", "🗝️ فك التشفير"])

with tab1:
    st.header("تشفير النص")
    text_to_encrypt = st.text_area("أدخل النص المراد تشفيره:", height=150)

    if st.button("تشفير النص"):
        if text_to_encrypt:
            encrypted_data = complex_encrypt(text_to_encrypt)
            st.session_state.encrypted_text = encrypted_data
            st.session_state.show_encrypted = True
            st.success("تم التشفير بنجاح!")

    if 'show_encrypted' in st.session_state and st.session_state.show_encrypted:
        encrypted_text = st.session_state.encrypted_text

        # عرض النص المشفر مع زر نسخ
        components.html(f"""
            <textarea id="encryptedText" style="width:100%; height:150px; background-color:#111; color:white; padding:10px; border-radius:5px;">{encrypted_text}</textarea>
            <button onclick="copyToClipboard()" style="margin-top:10px; padding:10px 20px; background-color:#4CAF50; color:white; border:none; border-radius:5px; cursor:pointer;">📋 نسخ النص</button>

            <script>
            function copyToClipboard() {{
                var copyText = document.getElementById("encryptedText");
                copyText.select();
                document.execCommand("copy");
                alert("✅ تم نسخ النص بنجاح!");
            }}
            </script>
        """, height=250)

with tab2:
    st.header("فك التشفير")
    enc_data = st.text_area("أدخل النص المشفر هنا", height=200)

    if st.button("فك التشفير"):
        if enc_data:
            try:
                parts = enc_data.split('|')
                if len(parts) != 4:
                    st.error("❌ النص المشفر غير صالح")
                encrypted_key, iv, encrypted_message, private_key = parts
                key_aes = decrypt_rsa(encrypted_key, private_key)
                decrypted_message = decrypt_aes(encrypted_message, key_aes, iv)
                st.success("تم فك التشفير بنجاح!")
                st.text_area("النص الأصلي", decrypted_message, height=150)
            except Exception as e:
                st.error(f"❌ خطأ أثناء فك التشفير: {str(e)}")
        else:
            st.warning("⚠️ الرجاء إدخال النص المشفر.")
