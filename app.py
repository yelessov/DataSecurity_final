import streamlit as st
import src.rsa_tools as rsa_tools
import pandas as pd
import time
from src.auth_manager import AuthManager
from src.audit_chain import Blockchain
from src.brute_force import ParallelCracker
import src.encryption as crypto

# Page configuration: title and layout for the Streamlit app
st.set_page_config(page_title="SecureSystem & Blockchain", layout="wide")

# Initialize shared objects and cache them in the Streamlit session state
if 'auth' not in st.session_state:
    st.session_state.auth = AuthManager()
if 'audit' not in st.session_state:
    st.session_state.audit = Blockchain()
if 'cracker' not in st.session_state:
    st.session_state.cracker = ParallelCracker()

auth = st.session_state.auth
audit = st.session_state.audit
cracker = st.session_state.cracker

# Sidebar menu
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to:", ["User Dashboard (User)", "Hacker Panel (Attack)", "Blockchain Audit (Admin)"])

# ==========================================
# Page 1: User dashboard (Login / Registration / AES secret storage)
# ==========================================
if page == "User Dashboard (User)":
    st.title("🔐 Secure Login (Identity Management)")

    tab1, tab2, tab3 = st.tabs(["Login", "Register", "RSA Signature (Digital Signature)"])

    # Login tab: username/password entry and simple auth check
    with tab1:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            user_data = auth.get_user_data(username)
            if user_data:
                # This is a simple demo password check — do not use in production.
                st.session_state['logged_user'] = username
                st.session_state['logged_pass'] = password # Keep password in session briefly for AES key derivation
                st.session_state['user_salt'] = user_data['salt']
                st.session_state['user_hash'] = user_data['hash']
                
                # Compute the SHA-256 hash and compare with stored value
                import hashlib
                check = hashlib.sha256((password + user_data['salt']).encode()).hexdigest()
                if check == user_data['hash']:
                    st.success(f"Добро пожаловать, {username}!")
                    audit.add_event(f"Login Success: {username}")
                else:
                    st.error("Неверный пароль")
                    st.session_state['logged_user'] = None
            else:
                st.error("User not found")

    # Registration tab: create a new user account
    with tab2:
        new_user = st.text_input("New username")
        new_pass = st.text_input("New password", type="password")
        if st.button("Register"):
            if auth.register(new_user, new_pass):
                st.success("Аккаунт создан! Теперь войдите.")
                audit.add_event(f"User Registered: {new_user}")
            else:
                st.warning("Пользователь уже существует.")

    # RSA Digital Signature tab: generate keys, sign and verify documents
    with tab3:
        st.header("🔏 Digital Signature (Non-repudiation)")
        
        # Make sure the user is logged in before allowing key operations
        if not st.session_state.get('logged_user'):
            st.warning("Please log in first (Login tab).")
        else:
            current_user = st.session_state['logged_user']
            
            # See if RSA keys already exist in the session (in a real app you'd persist them)
            if 'rsa_priv' not in st.session_state:
                st.info("You don't have RSA keys yet. Generate them.")
                if st.button("Generate RSA Key Pair (Public/Private)"):
                    priv, pub = rsa_tools.generate_key_pair()
                    st.session_state['rsa_priv'] = priv
                    st.session_state['rsa_pub'] = pub
                    
                    # Record key generation in the audit blockchain (we log the public key hash)
                    audit.add_event(f"User {current_user} generated RSA KeyPair. Public Key hash: {hash(pub)}")
                    st.success("Keys generated!")
                    st.rerun() # Refresh the page so the UI shows the new keys

            # If keys are available, show the signing UI
            if 'rsa_priv' in st.session_state:
                col_k1, col_k2 = st.columns(2)
                with col_k1:
                    st.markdown("🔑 **Your Public Key (visible to others):**")
                    st.code(st.session_state['rsa_pub'], language='text')
                with col_k2:
                    st.markdown("🗝️ **Your Private Key (secret):**")
                    st.code(st.session_state['rsa_priv'][:100] + "...", language='text') # Don't expose the full private key

                st.divider()
                st.subheader("Sign a document")
                
                # Text area where the user can enter the document to sign
                doc_text = st.text_area("Enter document text:", "I, admin, grant access.")
                
                if st.button("Sign document"):
                    # Create the digital signature for the provided text
                    signature = rsa_tools.sign_message(st.session_state['rsa_priv'], doc_text)
                    st.session_state['last_signature'] = signature
                    st.session_state['last_doc'] = doc_text
                    
                    st.success("Document signed!")
                    audit.add_event(f"User {current_user} signed a document (RSA)")
                
                # Display the generated signature and verification controls
                if 'last_signature' in st.session_state:
                    st.markdown("**Result (Digital Signature):**")
                    st.code(st.session_state['last_signature'])
                    
                    st.divider()
                    st.subheader("🔍 Verify Signature")
                    st.markdown("Anyone with your Public Key can verify this.")
                    
                    # Allow any user to paste a message and signature and verify them with the public key
                    check_msg = st.text_input("Text to verify", value=st.session_state['last_doc'])
                    check_sig = st.text_input("Signature to verify", value=st.session_state['last_signature'])
                    
                    if st.button("Verify signature"):
                        is_valid = rsa_tools.verify_signature(st.session_state['rsa_pub'], check_msg, check_sig)
                        if is_valid:
                            st.success("✅ SIGNATURE VALID! Document is authentic and author is confirmed.")
                        else:
                            st.error("❌ ERROR! Signature does not match. Document was altered or wrong key.")

    # AES area: encrypt/decrypt secrets for the logged-in user
    if st.session_state.get('logged_user'):
        st.divider()
        st.subheader(f"🛡️ AES-GCM secret storage for {st.session_state['logged_user']}")
        
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Save a secret**")
            secret_text = st.text_area("Enter data (card number, note):")
            if st.button("Encrypt & Save"):
                enc = crypto.encrypt_secret(st.session_state['logged_pass'], st.session_state['user_salt'], secret_text)
                auth.save_secret(st.session_state['logged_user'], enc)
                st.success("Data encrypted and saved to DB!")
                audit.add_event(f"User {st.session_state['logged_user']} updated AES secret")

        with col2:
            st.markdown("**Read secret**")
            if st.button("Decrypt from DB"):
                blob = auth.get_secret(st.session_state['logged_user'])
                if blob:
                    try:
                        dec = crypto.decrypt_secret(st.session_state['logged_pass'], st.session_state['user_salt'], blob)
                        st.info(f"🔓 YOUR SECRET: {dec}")
                        audit.add_event(f"User {st.session_state['logged_user']} decrypted secret")
                    except:
                        st.error("Decryption error!")
                else:
                    st.warning("No secrets found.")

# ==========================================
# PAGE 2: HACKER PANEL (Brute Force)
# ==========================================
elif page == "Hacker Panel (Attack)":
    st.title("☠️ Attack Control Panel")
    st.markdown("Demonstration of weak password vulnerabilities and dictionary attack speed.")

    target_user = st.text_input("Target username:")
    
    if st.button("START ATTACK"):
        user_data = auth.get_user_data(target_user)
        if not user_data:
            st.error("User not found in DB.")
        else:
            st.warning(f"Revealed hash: {user_data['hash'][:15]}... | Salt: {user_data['salt'][:10]}...")
            
            audit.add_event(f"SECURITY ALERT: Brute-force started on {target_user}")

            # Show a spinner while the cracker runs in parallel across CPU cores
            with st.spinner('Starting parallel processes on all CPU cores...'):
                start_time = time.time()
                result = cracker.crack(user_data['hash'], user_data['salt'])
                end_time = time.time()
            
            if result:
                st.error(f"❌ PASSWORD CRACKED: {result}")
                st.metric(label="Crack time", value=f"{end_time - start_time:.4f} sec")
                audit.add_event(f"CRITICAL: User {target_user} PWNED. Password: {result}")
            else:
                st.success("✅ Password not found in dictionary (safe).")
                audit.add_event(f"Attack Failed: {target_user} is safe")

# ==========================================
# Page 3: Blockchain audit viewer
# ==========================================
elif page == "Blockchain Audit (Admin)":
    st.title("🔗 Event Ledger (Blockchain Log)")
    
    # Controls for refreshing and verifying the audit log
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Refresh Log"):
            st.session_state.audit = Blockchain() # Reload from file
    with col2:
        if st.button("Verify Integrity"):
            if audit.is_chain_valid():
                st.success("✅ INTEGRITY VERIFIED. Data unchanged.")
            else:
                st.error("🚨 WARNING! INTEGRITY BROKEN! Logs have been tampered.")

    # Prepare the blockchain data and show it as a Pandas table
    chain_data = [b.to_dict() for b in audit.chain]
    df = pd.DataFrame(chain_data)
    
    # Render the audit log table in the UI
    st.dataframe(df, use_container_width=True)

    # Simple visualization of the hash pointers between recent blocks
    st.markdown("### Hash Pointer Visualization")
    for block in audit.chain[-3:]: # Show last 3
        st.text(f"Block {block.index} [Hash: {block.hash[:10]}...] -> Prev: {block.prev_hash[:10]}...")
        st.caption("  ⬇  ")