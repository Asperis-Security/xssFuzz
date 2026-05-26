#!/bin/bash

# Function to detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$ID
    else
        echo "Unable to detect OS."
        exit 1
    fi
}

# Function to install Chromium and ChromiumDriver
install_chromium() {
    echo "Detected OS: $OS_NAME"

    case "$OS_NAME" in
        ubuntu | debian | kali)
            echo "Installing Chromium and ChromiumDriver on $OS_NAME..."
            sudo apt update
            sudo apt install -y chromium chromium-driver
            ;;
        pop | neon | zorin | elementary | linuxmint)
            echo "Installing Chromium and ChromiumDriver on $OS_NAME (Ubuntu-based)..."
            sudo apt update
            sudo apt install -y chromium-browser chromium-chromedriver
            ;;
        *)
            echo "OS $OS_NAME is not directly supported by this script."
            echo "Please install Chromium and ChromiumDriver manually for your OS."
            exit 1
            ;;
    esac

    # Verify installation
    if command -v chromium >/dev/null 2>&1 && command -v chromedriver >/dev/null 2>&1; then
        echo "Chromium and ChromiumDriver installed successfully."
        echo "Chromium version: $(chromium --version)"
        echo "ChromiumDriver version: $(chromedriver --version)"
    else
        echo "Installation failed. Please check for errors and try manually."
    fi
}

# Main script execution
detect_os
install_chromium
