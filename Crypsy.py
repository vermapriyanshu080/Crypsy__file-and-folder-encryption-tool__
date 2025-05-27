import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import json
import base64
from PIL import Image, ImageTk
import io
from pydub import AudioSegment
import cv2
import time
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
import threading
import math

class GradientFrame(tk.Canvas):
    def __init__(self, parent, color1, color2, **kwargs):
        tk.Canvas.__init__(self, parent, **kwargs)
        self.color1 = color1
        self.color2 = color2
        self.bind("<Configure>", self._draw_gradient)

    def _draw_gradient(self, event=None):
        self.delete("gradient")
        width = self.winfo_width()
        height = self.winfo_height()
        
        for i in range(height):
            # Calculate gradient color
            r1, g1, b1 = self.winfo_rgb(self.color1)
            r2, g2, b2 = self.winfo_rgb(self.color2)
            r = r1 + (r2 - r1) * i // height
            g = g1 + (g2 - g1) * i // height
            b = b1 + (b2 - b1) * i // height
            color = f'#{r:04x}{g:04x}{b:04x}'
            self.create_line(0, i, width, i, fill=color, tags="gradient")

class FileVaultGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Vault")
        self.root.geometry("1000x800")
        
        # Auto-lock settings
        self.auto_lock_time = 300  # 5 minutes in seconds
        self.last_activity = time.time()
        self.is_locked = False
        
        # Create gradient background
        self.gradient_frame = GradientFrame(
            self.root,
            "#000000",  # Black
            "#00FF9D",  # Neon green
            highlightthickness=0
        )
        self.gradient_frame.pack(fill=tk.BOTH, expand=True)

        # Initialize vault properties
        self.metadata_file = "vault_metadata.json"
        self.metadata = self._load_metadata()
        self.salt = b'vault_salt_123'
        
        # Security logs password
        self.security_password = "admin123"
        
        # Create security folder if it doesn't exist
        self.security_folder = "security_logs"
        if not os.path.exists(self.security_folder):
            os.makedirs(self.security_folder)

        self._create_styles()
        self._create_widgets()
        
        # Start auto-lock timer
        self._start_auto_lock_timer()
        
        # Bind activity events
        self._bind_activity_events()

    def _bind_activity_events(self):
        """Bind events to track user activity"""
        events = ['<Key>', '<Button-1>', '<Button-2>', '<Button-3>', '<Motion>']
        for event in events:
            self.root.bind(event, self._update_activity)

    def _update_activity(self, event=None):
        """Update last activity time"""
        self.last_activity = time.time()
        if self.is_locked:
            self._unlock_application()

    def _start_auto_lock_timer(self):
        """Start the auto-lock timer"""
        self._check_auto_lock()
        self.root.after(1000, self._start_auto_lock_timer)  # Check every second

    def _check_auto_lock(self):
        """Check if application should be locked"""
        if not self.is_locked and (time.time() - self.last_activity) > self.auto_lock_time:
            self._lock_application()

    def _lock_application(self):
        """Lock the application"""
        self.is_locked = True
        # Disable all buttons and widgets
        for child in self.root.winfo_children():
            if isinstance(child, (ttk.Button, ttk.Radiobutton)):
                child.configure(state='disabled')
        
        # Show lock screen
        self._show_lock_screen()

    def _unlock_application(self):
        """Unlock the application"""
        password = self._get_password("Enter Password to Unlock")
        if password == self.security_password:
            self.is_locked = False
            # Enable all buttons and widgets
            for child in self.root.winfo_children():
                if isinstance(child, (ttk.Button, ttk.Radiobutton)):
                    child.configure(state='normal')
            # Hide lock screen
            if hasattr(self, 'lock_screen'):
                self.lock_screen.destroy()
        else:
            messagebox.showerror("Error", "Incorrect password!")

    def _show_lock_screen(self):
        """Show the lock screen"""
        self.lock_screen = tk.Toplevel(self.root)
        self.lock_screen.title("Application Locked")
        self.lock_screen.geometry("400x200")
        self.lock_screen.configure(bg='#2C3E50')
        self.lock_screen.transient(self.root)
        self.lock_screen.grab_set()

        # Center the window
        self.lock_screen.update_idletasks()
        width = self.lock_screen.winfo_width()
        height = self.lock_screen.winfo_height()
        x = (self.lock_screen.winfo_screenwidth() // 2) - (width // 2)
        y = (self.lock_screen.winfo_screenheight() // 2) - (height // 2)
        self.lock_screen.geometry(f'{width}x{height}+{x}+{y}')

        # Add lock message
        ttk.Label(
            self.lock_screen,
            text="Application Locked",
            font=('Segoe UI', 16, 'bold'),
            background='#2C3E50',
            foreground='white'
        ).pack(pady=20)

        ttk.Label(
            self.lock_screen,
            text="Enter password to unlock",
            font=('Segoe UI', 12),
            background='#2C3E50',
            foreground='#BDC3C7'
        ).pack(pady=10)

        # Add unlock button
        ttk.Button(
            self.lock_screen,
            text="Unlock",
            command=self._unlock_application,
            style='Custom.TButton'
        ).pack(pady=20)

    def _create_styles(self):
        style = ttk.Style()
        
        # Configure the theme
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TFrame', background='#1E1E2E')  # Darker background
        style.configure('TLabelframe', background='#1E1E2E', foreground='white')
        style.configure('TLabelframe.Label', background='#1E1E2E', foreground='#00FF9D', font=('Helvetica', 10, 'bold'))
        
        # Button styles
        style.configure('Custom.TButton',
                       padding=10,
                       font=('Helvetica', 10, 'bold'),
                       background='#00FF9D',  # Bright neon green
                       foreground='#1E1E2E')  # Dark background
        style.map('Custom.TButton',
                 background=[('active', '#00CC7D')],  # Darker green on hover
                 foreground=[('active', '#1E1E2E')])
        
        # Label styles
        style.configure('Brand.TLabel',
                       font=('Segoe UI', 36, 'bold'),
                       background='#1E1E2E',
                       foreground='#00FF9D',  # Bright neon green
                       padding=5)
        
        style.configure('Title.TLabel',
                       font=('Segoe UI', 24, 'bold'),
                       background='#1E1E2E',
                       foreground='#00FF9D',  # Bright neon green
                       padding=10)
        
        style.configure('Subtitle.TLabel',
                       font=('Segoe UI', 12),
                       background='#1E1E2E',
                       foreground='#FFFFFF',  # Pure white
                       padding=5)
        
        # Radio button styles
        style.configure('FileType.TRadiobutton',
                       font=('Segoe UI', 10),
                       background='#1E1E2E',
                       foreground='#FFFFFF',  # Pure white
                       padding=5)
        style.map('FileType.TRadiobutton',
                 background=[('active', '#1E1E2E')],
                 foreground=[('active', '#00FF9D')])  # Bright neon green on hover
        
        # Status label style
        style.configure('Status.TLabel',
                       font=('Segoe UI', 10),
                       background='#1E1E2E',
                       foreground='#00FF9D',  # Bright neon green
                       padding=5)

    def _create_widgets(self):
        # Main container
        main_container = ttk.Frame(self.gradient_frame, style='TFrame')
        self.gradient_frame.create_window(0, 0, anchor='nw', window=main_container, tags='main')
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Make the window size track the frame size for scrolling if needed (optional but good practice)
        main_container.bind("<Configure>", lambda e: self.gradient_frame.configure(scrollregion = self.gradient_frame.bbox("all")))

        # Title section
        title_frame = ttk.Frame(main_container, style='TFrame')
        title_frame.pack(fill=tk.X, pady=(0, 20))

        # Create brand name with elegant styling
        brand_container = ttk.Frame(title_frame, style='TFrame')
        brand_container.pack(pady=(0, 5))

        # Create a canvas for the stylish title
        title_canvas = tk.Canvas(
            brand_container,
            width=400,
            height=80,
            bg='#1E1E2E',
            highlightthickness=0
        )
        title_canvas.pack()

        # Add main title with glow effect
        title_canvas.create_text(
            200, 40,
            text="Crypsy",
            font=('Segoe UI', 48, 'bold'),
            fill='#00FF9D',
            tags='title'
        )

        # Re-add the subtitle below the Crypsy title canvas
        subtitle_label = ttk.Label(
            title_frame,
            text="Protect your files with advanced encryption",
            style='Subtitle.TLabel'
        )
        subtitle_label.pack()
        
        # Add hover effect to subtitle
        def on_subtitle_enter(e):
            subtitle_label.configure(foreground='#00FF9D')
        def on_subtitle_leave(e):
            subtitle_label.configure(foreground='#FFFFFF')
        subtitle_label.bind('<Enter>', on_subtitle_enter)
        subtitle_label.bind('<Leave>', on_subtitle_leave)

        # File type selection frame
        self.file_type_frame = ttk.LabelFrame(
            main_container,
            text="Select File Type",
            padding="15",
            style='TLabelframe'
        )
        self.file_type_frame.pack(fill=tk.X, pady=10, padx=20)
        
        # Add hover effect to file type labelframe title
        def on_filetype_enter(e):
            self.file_type_frame.configure(foreground='#00FF9D')
        def on_filetype_leave(e):
            self.file_type_frame.configure(foreground='white')
        self.file_type_frame.bind('<Enter>', on_filetype_enter)
        self.file_type_frame.bind('<Leave>', on_filetype_leave)

        self.file_type = tk.StringVar(value="text")
        
        # Create a frame for radio buttons
        radio_frame = ttk.Frame(self.file_type_frame, style='TFrame')
        radio_frame.pack(fill=tk.X, padx=10)

        # Radio buttons with icons
        file_types = [
            ("Text File", "text", "📄"),
            ("Image File", "image", "🖼️"),
            ("Audio File", "audio", "🎵"),
            ("Video File", "video", "🎥")
        ]

        # Create a container for centered icons
        icon_container = ttk.Frame(radio_frame, style='TFrame')
        icon_container.pack(fill=tk.X, pady=(0, 10))

        # Add icons in a centered row
        for text, value, icon in file_types:
            icon_frame = ttk.Frame(icon_container, style='TFrame')
            icon_frame.pack(side=tk.LEFT, expand=True)
            
            icon_label = ttk.Label(
                icon_frame,
                text=icon,
                font=('Segoe UI', 24),
                background='#1E1E2E',
                foreground='#00FF9D',
                cursor='hand2'
            )
            icon_label.pack()
            
            # Add hover effect
            def on_enter(e, label=icon_label):
                label.configure(foreground='#00FF9D')
                label.configure(font=('Segoe UI', 28, 'bold'))
            
            def on_leave(e, label=icon_label):
                label.configure(foreground='#FFFFFF')
                label.configure(font=('Segoe UI', 24))
            
            icon_label.bind('<Enter>', on_enter)
            icon_label.bind('<Leave>', on_leave)

        # Add radio buttons below icons
        radio_container = ttk.Frame(radio_frame, style='TFrame')
        radio_container.pack(fill=tk.X)

        for text, value, _ in file_types:
            btn_frame = ttk.Frame(radio_container, style='TFrame')
            btn_frame.pack(side=tk.LEFT, expand=True)
            
            radio_btn = ttk.Radiobutton(
                btn_frame,
                text=text,
                variable=self.file_type,
                value=value,
                style='FileType.TRadiobutton'
            )
            radio_btn.pack()
            
            # Add hover effect for radio button text
            def on_radio_enter(e, btn=radio_btn):
                btn.configure(foreground='#00FF9D')
            
            def on_radio_leave(e, btn=radio_btn):
                btn.configure(foreground='#FFFFFF')
            
            radio_btn.bind('<Enter>', on_radio_enter)
            radio_btn.bind('<Leave>', on_radio_leave)

        # Buttons frame
        button_frame = ttk.Frame(main_container, style='TFrame')
        button_frame.pack(pady=30)

        # Create buttons with icons and organize them in a grid
        buttons = [
            # Row 1: Folder operations
            ("📁 Encrypt Folder", self._encrypt_folder, 0, 0),
            ("📂 Decrypt Folder", self._decrypt_folder, 0, 1),
            # Row 2: File operations
            ("🔒 Encrypt File", self._encrypt_file, 1, 0),
            ("🔓 Decrypt File", self._decrypt_file, 1, 1),
            # Row 3: Other operations
            ("📋 View File Metadata", self._show_metadata, 2, 0),
            ("🔍 View Security Logs", self._show_security_logs, 2, 1)
        ]

        # Configure grid
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)

        # Create and place buttons in grid with hover effects
        for text, command, row, col in buttons:
            btn = ttk.Button(
                button_frame,
                text=text,
                command=command,
                style='Custom.TButton',
                width=25
            )
            btn.grid(row=row, column=col, padx=10, pady=10, sticky='ew')
            
            # Add hover effect for buttons
            def on_button_enter(e, button=btn):
                button.config(style='Custom.TButton:active')
                button.config(width=27) # Enlarge slightly on hover
            def on_button_leave(e, button=btn):
                button.config(style='Custom.TButton')
                button.config(width=25) # Return to original size
            btn.bind('<Enter>', on_button_enter)
            btn.bind('<Leave>', on_button_leave)

        # Add some spacing between rows
        button_frame.grid_rowconfigure(0, pad=10)
        button_frame.grid_rowconfigure(1, pad=10)
        button_frame.grid_rowconfigure(2, pad=10)

        # Status frame
        self.status_frame = ttk.Frame(main_container, style='TFrame')
        self.status_frame.pack(fill=tk.X, pady=20, padx=20)

        self.status_label = ttk.Label(
            self.status_frame,
            text="Ready",
            style='Status.TLabel'
        )
        self.status_label.pack()
        
        # Add hover effect to status label
        def on_status_enter(e):
            self.status_label.configure(foreground='#FFFFFF') # White on hover
        def on_status_leave(e):
            self.status_label.configure(foreground='#00FF9D') # Neon green normally
        self.status_label.bind('<Enter>', on_status_enter)
        self.status_label.bind('<Leave>', on_status_leave)

        # Add auto-lock settings to the interface
        settings_frame = ttk.LabelFrame(
            main_container,
            text="Security Settings",
            padding="15",
            style='TLabelframe'
        )
        settings_frame.pack(fill=tk.X, pady=0, padx=20) # Further reduced pady
        
        # Add hover effect to security settings labelframe title
        def on_settings_enter(e):
            settings_frame.configure(foreground='#00FF9D')
        def on_settings_leave(e):
            settings_frame.configure(foreground='white')
        settings_frame.bind('<Enter>', on_settings_enter)
        settings_frame.bind('<Leave>', on_settings_leave)

        # Auto-lock time selection
        ttk.Label(
            settings_frame,
            text="Auto-lock after:",
            style='Subtitle.TLabel'
        ).pack(side=tk.LEFT, padx=10)

        self.auto_lock_var = tk.StringVar(value="5")
        auto_lock_combo = ttk.Combobox(
            settings_frame,
            textvariable=self.auto_lock_var,
            values=["1", "3", "5", "10", "15", "30"],
            width=5,
            state="readonly"
        )
        auto_lock_combo.pack(side=tk.LEFT, padx=5)
        auto_lock_combo.bind('<<ComboboxSelected>>', self._update_auto_lock_time)

        ttk.Label(
            settings_frame,
            text="minutes",
            style='Subtitle.TLabel'
        ).pack(side=tk.LEFT, padx=5)

    def _load_metadata(self):
        if os.path.exists(self.metadata_file):
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        return {}

    def _save_metadata(self):
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=4)

    def _derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def _get_password(self, title):
        password_window = tk.Toplevel(self.root)
        password_window.title(title)
        password_window.geometry("400x200")
        password_window.configure(bg='#2C3E50')
        password_window.transient(self.root)
        password_window.grab_set()

        # Center the window
        password_window.update_idletasks()
        width = password_window.winfo_width()
        height = password_window.winfo_height()
        x = (password_window.winfo_screenwidth() // 2) - (width // 2)
        y = (password_window.winfo_screenheight() // 2) - (height // 2)
        password_window.geometry(f'{width}x{height}+{x}+{y}')

        password_var = tk.StringVar()
        result = {'password': None}

        def on_ok():
            result['password'] = password_var.get()
            password_window.destroy()

        # Style the password window
        ttk.Label(
            password_window,
            text="Enter Password:",
            font=('Helvetica', 12, 'bold'),
            background='#2C3E50',
            foreground='white'
        ).pack(pady=20)

        password_entry = ttk.Entry(
            password_window,
            textvariable=password_var,
            show="•",
            font=('Helvetica', 12),
            width=30
        )
        password_entry.pack(pady=10)
        password_entry.focus()

        ttk.Button(
            password_window,
            text="OK",
            command=on_ok,
            style='Custom.TButton'
        ).pack(pady=20)

        self.root.wait_window(password_window)
        return result['password']

    def _get_file_types(self):
        if self.file_type.get() == "image":
            return [("Image files", "*.png *.jpg *.jpeg *.bmp *.gif")]
        elif self.file_type.get() == "audio":
            return [("Audio files", "*.mp3 *.wav *.ogg *.flac *.m4a")]
        elif self.file_type.get() == "video":
            return [("Video files", "*.mp4 *.avi *.mkv *.mov *.wmv")]
        return [("Text files", "*.txt"), ("All files", "*.*")]

    def _show_loading_animation(self, title, message):
        """Show a loading animation window"""
        loading_window = tk.Toplevel(self.root)
        loading_window.title(title)
        loading_window.geometry("400x250")
        loading_window.configure(bg='#2C3E50')
        loading_window.transient(self.root)
        loading_window.grab_set()

        # Center the window
        loading_window.update_idletasks()
        width = loading_window.winfo_width()
        height = loading_window.winfo_height()
        x = (loading_window.winfo_screenwidth() // 2) - (width // 2)
        y = (loading_window.winfo_screenheight() // 2) - (height // 2)
        loading_window.geometry(f'{width}x{height}+{x}+{y}')

        # Add message
        message_label = ttk.Label(
            loading_window,
            text=message,
            font=('Helvetica', 12),
            background='#2C3E50',
            foreground='white'
        )
        message_label.pack(pady=20)

        # Add progress percentage label
        progress_label = ttk.Label(
            loading_window,
            text="0%",
            font=('Helvetica', 14, 'bold'),
            background='#2C3E50',
            foreground='#3498DB'
        )
        progress_label.pack(pady=5)

        # Add progress bar
        progress = ttk.Progressbar(
            loading_window,
            length=300,
            mode='determinate'
        )
        progress.pack(pady=10)

        # Add spinning animation
        canvas = tk.Canvas(
            loading_window,
            width=50,
            height=50,
            bg='#2C3E50',
            highlightthickness=0
        )
        canvas.pack(pady=10)

        def draw_spinner(angle=0):
            canvas.delete("all")
            # Draw spinning circle
            canvas.create_arc(10, 10, 40, 40, start=angle, extent=300, fill='#3498DB')
            canvas.create_arc(10, 10, 40, 40, start=angle+300, extent=60, fill='#2C3E50')
            # Update angle for next frame
            angle = (angle + 10) % 360
            loading_window.after(50, lambda: draw_spinner(angle))

        draw_spinner()

        return loading_window, progress, progress_label, message_label

    def _update_progress(self, progress, progress_label, message_label, value, message):
        """Update progress bar and labels"""
        progress['value'] = value
        progress_label.config(text=f"{value}%")
        message_label.config(text=message)
        progress.update()

    def _encrypt_file(self):
        file_path = filedialog.askopenfilename(
            title="Select file to encrypt",
            filetypes=self._get_file_types()
        )
        
        if not file_path:
            return

        password = self._get_password("Encryption Password")
        if not password:
            return

        # Show loading animation
        loading_window, progress, progress_label, message_label = self._show_loading_animation(
            "Encrypting",
            "🔒 Initializing encryption..."
        )

        def encryption_process():
            try:
                # Simulate initialization
                self._update_progress(progress, progress_label, message_label, 10, "🔒 Reading file...")
                time.sleep(0.5)  # Add small delay for visibility

                key = self._derive_key(password)
                self._update_progress(progress, progress_label, message_label, 30, "🔒 Generating encryption key...")
                time.sleep(0.5)

                fernet = Fernet(key)
                self._update_progress(progress, progress_label, message_label, 40, "🔒 Preparing encryption...")
                time.sleep(0.5)

                if self.file_type.get() == "image":
                    self._update_progress(progress, progress_label, message_label, 50, "🔒 Processing image...")
                    with Image.open(file_path) as img:
                        img_byte_arr = io.BytesIO()
                        img.save(img_byte_arr, format=img.format)
                        img_byte_arr = img_byte_arr.getvalue()
                        encrypted_data = fernet.encrypt(img_byte_arr)
                elif self.file_type.get() == "audio":
                    self._update_progress(progress, progress_label, message_label, 50, "🔒 Processing audio...")
                    audio = AudioSegment.from_file(file_path)
                    audio_byte_arr = io.BytesIO()
                    audio.export(audio_byte_arr, format=os.path.splitext(file_path)[1][1:])
                    audio_byte_arr = audio_byte_arr.getvalue()
                    encrypted_data = fernet.encrypt(audio_byte_arr)
                elif self.file_type.get() == "video":
                    self._update_progress(progress, progress_label, message_label, 50, "🔒 Processing video...")
                    with open(file_path, 'rb') as f:
                        video_data = f.read()
                    encrypted_data = fernet.encrypt(video_data)
                else:
                    self._update_progress(progress, progress_label, message_label, 50, "🔒 Processing text...")
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                    encrypted_data = fernet.encrypt(file_data)

                self._update_progress(progress, progress_label, message_label, 70, "🔒 Encrypting data...")
                time.sleep(0.5)

                encrypted_file_path = f"{file_path}.enc"
                with open(encrypted_file_path, 'wb') as f:
                    f.write(encrypted_data)
                
                self._update_progress(progress, progress_label, message_label, 80, "🔒 Saving encrypted file...")
                time.sleep(0.5)

                os.remove(file_path)

                self.metadata[encrypted_file_path] = {
                    'original_name': file_path,
                    'encrypted_date': datetime.now().isoformat(),
                    'last_opened': None,
                    'locked': True,
                    'file_type': self.file_type.get()
                }
                self._save_metadata()

                self._update_progress(progress, progress_label, message_label, 100, "🔒 Encryption complete!")
                time.sleep(0.5)

                # Update UI in main thread
                self.root.after(0, lambda: self._encryption_complete(loading_window, encrypted_file_path))

            except Exception as e:
                # Update UI in main thread
                self.root.after(0, lambda: self._encryption_error(loading_window, str(e)))

        # Start encryption in separate thread
        threading.Thread(target=encryption_process, daemon=True).start()

    def _encryption_complete(self, loading_window, encrypted_file_path):
        loading_window.destroy()
        self.status_label.config(text=f"File encrypted successfully: {encrypted_file_path}")
        messagebox.showinfo("Success", f"File encrypted successfully!\nThe file has been encrypted and saved as: {encrypted_file_path}")

    def _encryption_error(self, loading_window, error_message):
        loading_window.destroy()
        self.status_label.config(text=f"Error during encryption: {error_message}")
        messagebox.showerror("Error", f"Encryption failed: {error_message}")

    def _decrypt_file(self):
        file_path = filedialog.askopenfilename(
            title="Select file to decrypt",
            filetypes=[("Encrypted files", "*.enc")]
        )
        
        if not file_path:
            return

        if file_path not in self.metadata:
            messagebox.showerror("Error", "No metadata found for this file. It may not be encrypted or was encrypted with a different system.")
            return

        password = self._get_password("Decryption Password")
        if not password:
            return

        # Show loading animation
        loading_window, progress, progress_label, message_label = self._show_loading_animation(
            "Decrypting",
            "🔓 Initializing decryption..."
        )

        def decryption_process():
            try:
                # Simulate initialization
                self._update_progress(progress, progress_label, message_label, 10, "🔓 Reading encrypted file...")
                time.sleep(0.5)

                key = self._derive_key(password)
                self._update_progress(progress, progress_label, message_label, 30, "🔓 Generating decryption key...")
                time.sleep(0.5)

                fernet = Fernet(key)
                self._update_progress(progress, progress_label, message_label, 40, "🔓 Preparing decryption...")
                time.sleep(0.5)

                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()

                self._update_progress(progress, progress_label, message_label, 50, "🔓 Decrypting data...")
                time.sleep(0.5)

                try:
                    decrypted_data = fernet.decrypt(encrypted_data)
                except Exception as e:
                    # Update progress to show error
                    self._update_progress(progress, progress_label, message_label, 50, "❌ Decryption failed!")
                    time.sleep(0.5)
                    # Capture intruder image and ensure it's completed
                    self._capture_intruder()
                    # Wait a moment to ensure image is captured
                    time.sleep(1)
                    # Raise the exception to be caught by outer try-except
                    raise e

                original_path = self.metadata[file_path]['original_name']
                
                self._update_progress(progress, progress_label, message_label, 70, "🔓 Processing decrypted data...")
                time.sleep(0.5)

                if self.metadata[file_path].get('file_type') == 'image':
                    self._update_progress(progress, progress_label, message_label, 80, "🔓 Saving image...")
                    img = Image.open(io.BytesIO(decrypted_data))
                    img.save(original_path)
                elif self.metadata[file_path].get('file_type') == 'audio':
                    self._update_progress(progress, progress_label, message_label, 80, "🔓 Saving audio...")
                    audio = AudioSegment.from_file(io.BytesIO(decrypted_data))
                    audio.export(original_path, format=os.path.splitext(original_path)[1][1:])
                elif self.metadata[file_path].get('file_type') == 'video':
                    self._update_progress(progress, progress_label, message_label, 80, "🔓 Saving video...")
                    with open(original_path, 'wb') as f:
                        f.write(decrypted_data)
                else:
                    self._update_progress(progress, progress_label, message_label, 80, "🔓 Saving text...")
                    with open(original_path, 'wb') as f:
                        f.write(decrypted_data)

                os.remove(file_path)

                self.metadata[file_path]['last_opened'] = datetime.now().isoformat()
                self._save_metadata()

                self._update_progress(progress, progress_label, message_label, 100, "🔓 Decryption complete!")
                time.sleep(0.5)

                # Update UI in main thread
                self.root.after(0, lambda: self._decryption_complete(loading_window, original_path))

            except Exception as e:
                # Update progress to show error
                self._update_progress(progress, progress_label, message_label, 50, "❌ Decryption failed!")
                time.sleep(0.5)
                # Ensure intruder image is captured even if popup is closed
                self._capture_intruder()
                # Wait a moment to ensure image is captured
                time.sleep(1)
                # Update UI in main thread
                self.root.after(0, lambda: self._decryption_error(loading_window, str(e)))

        # Start decryption in separate thread
        threading.Thread(target=decryption_process, daemon=True).start()

    def _decryption_complete(self, loading_window, original_path):
        loading_window.destroy()
        self.status_label.config(text=f"File decrypted successfully: {original_path}")
        messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {original_path}")

    def _decryption_error(self, loading_window, error_message):
        loading_window.destroy()
        self.status_label.config(text=f"Error during decryption: {error_message}")
        messagebox.showerror("Decryption Failed", f"Decryption failed: {error_message}\n\nAn intruder alert has been triggered and the image has been captured.")

    def _show_metadata(self):
        file_path = filedialog.askopenfilename(
            title="Select file to view metadata",
            filetypes=[("Encrypted files", "*.enc")]
        )
        
        if not file_path:
            return

        if file_path in self.metadata:
            # Update last_opened timestamp when viewing metadata
            self.metadata[file_path]['last_opened'] = datetime.now().isoformat()
            self._save_metadata()
            
            metadata = self.metadata[file_path]
            metadata_text = f"""
File Metadata:
Original Name: {metadata['original_name']}
File Type: {metadata.get('file_type', 'text')}
Encrypted Date: {metadata['encrypted_date']}
Last Opened: {metadata['last_opened']}
Locked: {metadata['locked']}
"""
            messagebox.showinfo("File Metadata", metadata_text)
        else:
            messagebox.showinfo("File Metadata", "No metadata found for this file. It may not be encrypted or was encrypted with a different system.")

    def _verify_security_password(self):
        password_window = tk.Toplevel(self.root)
        password_window.title("Security Access")
        password_window.geometry("400x200")
        password_window.configure(bg='#2C3E50')
        password_window.transient(self.root)
        password_window.grab_set()

        # Center the window
        password_window.update_idletasks()
        width = password_window.winfo_width()
        height = password_window.winfo_height()
        x = (password_window.winfo_screenwidth() // 2) - (width // 2)
        y = (password_window.winfo_screenheight() // 2) - (height // 2)
        password_window.geometry(f'{width}x{height}+{x}+{y}')

        password_var = tk.StringVar()
        result = {'verified': False}

        def on_ok():
            if password_var.get() == self.security_password:
                result['verified'] = True
                password_window.destroy()
            else:
                messagebox.showerror("Error", "Incorrect password!")
                password_var.set("")

        ttk.Label(
            password_window,
            text="Enter Security Password:",
            font=('Helvetica', 12, 'bold'),
            background='#2C3E50',
            foreground='white'
        ).pack(pady=20)

        password_entry = ttk.Entry(
            password_window,
            textvariable=password_var,
            show="•",
            font=('Helvetica', 12),
            width=30
        )
        password_entry.pack(pady=10)
        password_entry.focus()

        ttk.Button(
            password_window,
            text="OK",
            command=on_ok,
            style='Custom.TButton'
        ).pack(pady=20)

        self.root.wait_window(password_window)
        return result['verified']

    def _show_security_logs(self):
        if not self._verify_security_password():
            return

        if not os.path.exists(self.security_folder):
            messagebox.showinfo("Security Logs", "No security logs found.")
            return

        # Create a new window for security logs
        log_window = tk.Toplevel(self.root)
        log_window.title("Security Logs")
        log_window.geometry("800x600")
        log_window.configure(bg='#2C3E50')

        # Create a text widget with scrollbar
        frame = ttk.Frame(log_window, style='TFrame')
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text_widget = tk.Text(
            frame,
            yscrollcommand=scrollbar.set,
            font=('Consolas', 10),
            bg='#34495E',
            fg='white',
            insertbackground='white'
        )
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)

        # Read and display the log file
        log_file = os.path.join(self.security_folder, "security_log.txt")
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                text_widget.insert(tk.END, f.read())

        # List all captured images
        text_widget.insert(tk.END, "\n\n📸 Captured Images:\n")
        for root, dirs, files in os.walk(self.security_folder):
            for file in files:
                if file.endswith('.jpg'):
                    full_path = os.path.join(root, file)
                    text_widget.insert(tk.END, f"📁 {full_path}\n")

        text_widget.config(state=tk.DISABLED)

        # Add a button to open the security folder
        def open_security_folder():
            os.startfile(self.security_folder)

        ttk.Button(
            log_window,
            text="📂 Open Security Folder",
            command=open_security_folder,
            style='Custom.TButton'
        ).pack(pady=20)

    def _update_gradient(self, event=None):
        self.gradient_frame._draw_gradient()

    def _encrypt_folder(self):
        folder_path = filedialog.askdirectory(title="Select folder to encrypt")
        if not folder_path:
            return

        password = self._get_password("Encryption Password")
        if not password:
            return

        try:
            key = self._derive_key(password)
            fernet = Fernet(key)
            
            # Create a progress window
            progress_window = tk.Toplevel(self.root)
            progress_window.title("Encrypting Folder")
            progress_window.geometry("400x150")
            progress_window.configure(bg='#2C3E50')
            progress_window.transient(self.root)
            progress_window.grab_set()

            # Center the window
            progress_window.update_idletasks()
            width = progress_window.winfo_width()
            height = progress_window.winfo_height()
            x = (progress_window.winfo_screenwidth() // 2) - (width // 2)
            y = (progress_window.winfo_screenheight() // 2) - (height // 2)
            progress_window.geometry(f'{width}x{height}+{x}+{y}')

            # Add progress label
            progress_label = ttk.Label(
                progress_window,
                text="Encrypting files...",
                font=('Helvetica', 10),
                background='#2C3E50',
                foreground='white'
            )
            progress_label.pack(pady=20)

            # Add progress bar
            progress_bar = ttk.Progressbar(
                progress_window,
                length=300,
                mode='determinate'
            )
            progress_bar.pack(pady=10)

            # Function to update progress
            def update_progress(current, total):
                progress = (current / total) * 100
                progress_bar['value'] = progress
                progress_label.config(text=f"Encrypting files... {current}/{total}")
                progress_window.update()

            # Get total number of files
            total_files = sum([len(files) for _, _, files in os.walk(folder_path)])
            processed_files = 0

            # Walk through the folder
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip already encrypted files
                    if file_path.endswith('.enc'):
                        continue

                    try:
                        # Determine file type
                        file_type = "text"
                        if file.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
                            file_type = "image"
                        elif file.lower().endswith(('.mp3', '.wav', '.ogg', '.flac', '.m4a')):
                            file_type = "audio"
                        elif file.lower().endswith(('.mp4', '.avi', '.mkv', '.mov', '.wmv')):
                            file_type = "video"

                        # Encrypt the file
                        if file_type == "image":
                            with Image.open(file_path) as img:
                                img_byte_arr = io.BytesIO()
                                img.save(img_byte_arr, format=img.format)
                                img_byte_arr = img_byte_arr.getvalue()
                                encrypted_data = fernet.encrypt(img_byte_arr)
                        elif file_type == "audio":
                            audio = AudioSegment.from_file(file_path)
                            audio_byte_arr = io.BytesIO()
                            audio.export(audio_byte_arr, format=os.path.splitext(file_path)[1][1:])
                            audio_byte_arr = audio_byte_arr.getvalue()
                            encrypted_data = fernet.encrypt(audio_byte_arr)
                        elif file_type == "video":
                            with open(file_path, 'rb') as f:
                                video_data = f.read()
                            encrypted_data = fernet.encrypt(video_data)
                        else:
                            with open(file_path, 'rb') as f:
                                file_data = f.read()
                            encrypted_data = fernet.encrypt(file_data)

                        # Create encrypted file
                        encrypted_file_path = f"{file_path}.enc"
                        with open(encrypted_file_path, 'wb') as f:
                            f.write(encrypted_data)

                        # Delete original file
                        os.remove(file_path)

                        # Store metadata
                        self.metadata[encrypted_file_path] = {
                            'original_name': file_path,
                            'encrypted_date': datetime.now().isoformat(),
                            'last_opened': None,
                            'locked': True,
                            'file_type': file_type
                        }

                        processed_files += 1
                        update_progress(processed_files, total_files)

                    except Exception as e:
                        print(f"Error encrypting {file_path}: {str(e)}")

            # Save metadata after all files are processed
            self._save_metadata()

            # Close progress window
            progress_window.destroy()

            self.status_label.config(text=f"Folder encrypted successfully: {folder_path}")
            messagebox.showinfo("Success", f"Folder encrypted successfully!\nAll files in {folder_path} have been encrypted.")

        except Exception as e:
            self.status_label.config(text=f"Error during folder encryption: {str(e)}")
            messagebox.showerror("Error", f"Folder encryption failed: {str(e)}")

    def _decrypt_folder(self):
        folder_path = filedialog.askdirectory(title="Select folder to decrypt")
        if not folder_path:
            return

        password = self._get_password("Decryption Password")
        if not password:
            return

        try:
            key = self._derive_key(password)
            fernet = Fernet(key)
            
            # Create a progress window
            progress_window = tk.Toplevel(self.root)
            progress_window.title("Decrypting Folder")
            progress_window.geometry("400x150")
            progress_window.configure(bg='#2C3E50')
            progress_window.transient(self.root)
            progress_window.grab_set()

            # Center the window
            progress_window.update_idletasks()
            width = progress_window.winfo_width()
            height = progress_window.winfo_height()
            x = (progress_window.winfo_screenwidth() // 2) - (width // 2)
            y = (progress_window.winfo_screenheight() // 2) - (height // 2)
            progress_window.geometry(f'{width}x{height}+{x}+{y}')

            # Add progress label
            progress_label = ttk.Label(
                progress_window,
                text="Decrypting files...",
                font=('Helvetica', 10),
                background='#2C3E50',
                foreground='white'
            )
            progress_label.pack(pady=20)

            # Add progress bar
            progress_bar = ttk.Progressbar(
                progress_window,
                length=300,
                mode='determinate'
            )
            progress_bar.pack(pady=10)

            # Function to update progress
            def update_progress(current, total):
                progress = (current / total) * 100
                progress_bar['value'] = progress
                progress_label.config(text=f"Decrypting files... {current}/{total}")
                progress_window.update()

            # Get total number of encrypted files
            total_files = sum([len([f for f in files if f.endswith('.enc')]) 
                             for _, _, files in os.walk(folder_path)])
            processed_files = 0

            # Walk through the folder
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if not file.endswith('.enc'):
                        continue

                    file_path = os.path.join(root, file)
                    
                    try:
                        # Get metadata
                        if file_path not in self.metadata:
                            print(f"No metadata found for {file_path}")
                            continue

                        metadata = self.metadata[file_path]
                        file_type = metadata.get('file_type', 'text')
                        original_path = metadata['original_name']

                        # Read and decrypt the file
                        with open(file_path, 'rb') as f:
                            encrypted_data = f.read()

                        try:
                            decrypted_data = fernet.decrypt(encrypted_data)
                        except Exception as e:
                            # Capture intruder image on failed decryption
                            self._capture_intruder()
                            raise Exception(f"Decryption failed: {str(e)}")

                        # Save decrypted file
                        if file_type == "image":
                            img = Image.open(io.BytesIO(decrypted_data))
                            img.save(original_path)
                        elif file_type == "audio":
                            audio = AudioSegment.from_file(io.BytesIO(decrypted_data))
                            audio.export(original_path, format=os.path.splitext(original_path)[1][1:])
                        elif file_type == "video":
                            with open(original_path, 'wb') as f:
                                f.write(decrypted_data)
                        else:
                            with open(original_path, 'wb') as f:
                                f.write(decrypted_data)

                        # Delete the encrypted file
                        os.remove(file_path)

                        # Update metadata
                        self.metadata[file_path]['last_opened'] = datetime.now().isoformat()
                        processed_files += 1
                        update_progress(processed_files, total_files)

                    except Exception as e:
                        print(f"Error decrypting {file_path}: {str(e)}")

            # Save metadata after all files are processed
            self._save_metadata()

            # Close progress window
            progress_window.destroy()

            self.status_label.config(text=f"Folder decrypted successfully: {folder_path}")
            messagebox.showinfo("Success", f"Folder decrypted successfully!\nAll encrypted files in {folder_path} have been decrypted.")

        except Exception as e:
            self.status_label.config(text=f"Error during folder decryption: {str(e)}")
            messagebox.showerror("Error", f"Folder decryption failed: {str(e)}")

    def _update_auto_lock_time(self, event=None):
        """Update auto-lock time when user changes it"""
        try:
            minutes = int(self.auto_lock_var.get())
            self.auto_lock_time = minutes * 60
        except ValueError:
            self.auto_lock_time = 300  # Default to 5 minutes

    def _capture_intruder(self):
        try:
            # Initialize camera
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                print("Failed to open camera")
                return
            
            # Wait for camera to initialize
            time.sleep(1)
            
            # Capture frame
            ret, frame = cap.read()
            if ret:
                # Create date-based folder structure
                current_date = datetime.now().strftime("%Y-%m-%d")
                date_folder = os.path.join(self.security_folder, current_date)
                if not os.path.exists(date_folder):
                    os.makedirs(date_folder)
                
                # Generate filename with timestamp
                timestamp = datetime.now().strftime("%H%M%S")
                filename = os.path.join(date_folder, f"intruder_{timestamp}.jpg")
                
                # Save the image
                cv2.imwrite(filename, frame)
                
                # Log the attempt
                log_file = os.path.join(self.security_folder, "security_log.txt")
                with open(log_file, "a") as f:
                    f.write(f"Failed decryption attempt at {datetime.now().isoformat()} - Image saved at: {filename}\n")
                
                # Send image via Telegram
                self._send_intruder_telegram(filename)
                
                print(f"Intruder image captured and saved at: {filename}")
            else:
                print("Failed to capture frame from camera")
            
            # Release camera
            cap.release()
            
        except Exception as e:
            print(f"Error capturing intruder image: {str(e)}")
            # Try to capture again after a short delay
            time.sleep(1)
            try:
                self._capture_intruder()
            except:
                print("Failed to capture intruder image after retry")

    def _send_intruder_telegram(self, image_path):
        try:
            # Telegram configuration
            bot_token = "8022063312:AAHUBW-KyUsCne0ZBRa-d52EoPGZo0uX5-w"  # Replace with your bot token
            chat_id = "5705185280"      # Replace with your chat ID
            
            # Prepare message
            message = f"🚨 Intruder Alert!\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            # Send message first
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            data = {
                "chat_id": chat_id,
                "text": message
            }
            response = requests.post(url, data=data)
            
            if response.status_code == 200:
                # Send image
                url = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
                files = {
                    'photo': open(image_path, 'rb')
                }
                data = {
                    'chat_id': chat_id,
                    'caption': 'Intruder Image'
                }
                response = requests.post(url, files=files, data=data)
                
                if response.status_code == 200:
                    print("Intruder alert sent successfully via Telegram!")
                else:
                    print(f"Error sending image to Telegram: {response.text}")
            else:
                print(f"Error sending message to Telegram: {response.text}")
                
        except Exception as e:
            print(f"Error sending Telegram alert: {str(e)}")

class FileVault:
    def __init__(self):
        self.metadata_file = "vault_metadata.json"
        self.metadata = self._load_metadata()
        self.salt = b'vault_salt_123'
        self.security_folder = "security_logs"
        if not os.path.exists(self.security_folder):
            os.makedirs(self.security_folder)

    def _load_metadata(self):
        if os.path.exists(self.metadata_file):
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        return {}

    def _save_metadata(self):
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=4)

    def _derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_file(self, file_path, password):
        try:
            key = self._derive_key(password)
            fernet = Fernet(key)

            with open(file_path, 'rb') as f:
                file_data = f.read()
            encrypted_data = fernet.encrypt(file_data)

            encrypted_path = f"{file_path}.enc"
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)

            self.metadata[encrypted_path] = {
                'original_name': file_path,
                'encrypted_date': datetime.now().isoformat(),
                'last_opened': None,
                'locked': True,
                'file_type': 'text'
            }
            self._save_metadata()

            return encrypted_path
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    def decrypt_file(self, file_path, password):
        try:
            key = self._derive_key(password)
            fernet = Fernet(key)

            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = fernet.decrypt(encrypted_data)

            decrypted_path = file_path.replace('.enc', '')
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_data)

            if file_path in self.metadata:
                self.metadata[file_path]['last_opened'] = datetime.now().isoformat()
                self._save_metadata()

            return decrypted_path
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

    def get_metadata(self):
        return self.metadata

def main():
    root = tk.Tk()
    app = FileVaultGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 
