import os
import json
import urllib.request
import threading
import subprocess
import tkinter as tk
from tkinter import messagebox
import zipfile
import platform

USER_AGENT = "Mozilla/5.0"
VERSIONS_DIR = "versions"
LIBRARIES_DIR = "libraries"
ASSETS_DIR = "assets"

class MinecraftLauncher(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Lunar Client Launcher - TLauncher Backend")
        self.geometry("400x300")
        self.versions = {}
        self.version_var = tk.StringVar()
        self.username = tk.StringVar(value="Player")
        self.setup_ui()
        self.load_versions_thread()

    def setup_ui(self):
        tk.Label(self, text="Select Version:").pack(pady=5)
        version_menu = tk.OptionMenu(self, self.version_var, "Loading...")
        version_menu.pack(pady=5)
        tk.Label(self, text="Username:").pack(pady=5)
        tk.Entry(self, textvariable=self.username).pack(pady=5)
        tk.Button(self, text="Launch", command=self.prepare_and_launch).pack(pady=20)

    def load_versions_thread(self):
        threading.Thread(target=self.load_version_manifest, daemon=True).start()

    def load_version_manifest(self):
        print("Loading version manifest...")
        url = "https://launchermeta.mojang.com/mc/game/version_manifest.json"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
            self.versions = {v["id"]: v["url"] for v in data["versions"]}
            self.after(0, self.update_version_list)
        except Exception as e:
            print(f"Error loading version manifest: {e}")
            self.after(0, lambda: messagebox.showerror("Error", f"Failed to load version manifest: {e}"))

    def update_version_list(self):
        menu = self.children["!optionmenu"]["menu"]
        menu.delete(0, "end")
        for version in self.versions.keys():
            menu.add_command(label=version, command=lambda v=version: self.version_var.set(v))
        self.version_var.set(list(self.versions.keys())[0] if self.versions else "No versions")

    def download_file(self, url, dest_path, description="file"):
        print(f"Downloading {description}: {os.path.basename(dest_path)}")
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        try:
            req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
            with urllib.request.urlopen(req) as response:
                with open(dest_path, 'wb') as out_file:
                    out_file.write(response.read())
            print(f"Finished downloading {description}")
        except Exception as e:
            print(f"Failed to download {description}: {e}")
            raise

    def is_library_allowed(self, lib, current_os):
        if "rules" not in lib:
            return True
        allow = False
        for rule in lib["rules"]:
            if rule["action"] == "allow":
                if "os" not in rule or rule["os"]["name"] == current_os:
                    allow = True
            elif rule["action"] == "disallow":
                if "os" in rule and rule["os"]["name"] == current_os:
                    return False
        return allow

    def download_version_files(self, version_id, version_url):
        print(f"Downloading files for {version_id}...")
        version_dir = os.path.join(VERSIONS_DIR, version_id)
        os.makedirs(version_dir, exist_ok=True)
        version_json_path = os.path.join(version_dir, f"{version_id}.json")
        if not os.path.exists(version_json_path):
            self.download_file(version_url, version_json_path, f"version JSON ({version_id})")
        
        with open(version_json_path, "r") as f:
            version_data = json.load(f)

        # Download client JAR
        client_jar_path = os.path.join(version_dir, f"{version_id}.jar")
        if not os.path.exists(client_jar_path):
            self.download_file(version_data["downloads"]["client"]["url"], client_jar_path, f"client JAR ({version_id})")

        # Download libraries and natives
        current_os = platform.system().lower()
        natives_dir = os.path.join(version_dir, "natives")
        os.makedirs(natives_dir, exist_ok=True)
        for lib in version_data.get("libraries", []):
            if self.is_library_allowed(lib, current_os):
                if "downloads" in lib and "artifact" in lib["downloads"]:
                    artifact = lib["downloads"]["artifact"]
                    lib_path = os.path.join(LIBRARIES_DIR, artifact["path"])
                    if not os.path.exists(lib_path):
                        self.download_file(artifact["url"], lib_path, f"library {lib['name']}")
                if "natives" in lib and current_os in lib["natives"]:
                    classifier = lib["natives"][current_os]
                    if "downloads" in lib and "classifiers" in lib["downloads"]:
                        native = lib["downloads"]["classifiers"][classifier]
                        native_path = os.path.join(natives_dir, f"{lib['name']}-{classifier}.jar")
                        if not os.path.exists(native_path):
                            self.download_file(native["url"], native_path, f"native {lib['name']}")
                        with zipfile.ZipFile(native_path, "r") as zip_ref:
                            zip_ref.extractall(natives_dir)

        # Download assets
        asset_index = version_data.get("assetIndex")
        if asset_index:
            idx_path = os.path.join(ASSETS_DIR, "indexes", f"{asset_index['id']}.json")
            if not os.path.exists(idx_path):
                self.download_file(asset_index["url"], idx_path, f"asset index ({asset_index['id']})")
            with open(idx_path, "r") as f:
                idx_data = json.load(f)
            for asset_name, info in idx_data["objects"].items():
                hash_val = info["hash"]
                asset_path = os.path.join(ASSETS_DIR, "objects", hash_val[:2], hash_val)
                if not os.path.exists(asset_path):
                    self.download_file(f"http://resources.download.minecraft.net/{hash_val[:2]}/{hash_val}", asset_path, f"asset ({asset_name})")
        return True

    def build_launch_command(self, version, username, ram, java_path):
        version_dir = os.path.join(VERSIONS_DIR, version)
        json_path = os.path.join(version_dir, f"{version}.json")
        with open(json_path, "r") as f:
            version_data = json.load(f)

        natives_dir = os.path.join(version_dir, "natives")
        version_jar = os.path.join(version_dir, f"{version}.jar")
        libraries = [os.path.join(LIBRARIES_DIR, lib["downloads"]["artifact"]["path"]) 
                     for lib in version_data["libraries"] if "artifact" in lib["downloads"]]
        classpath = os.pathsep.join([version_jar] + libraries)

        # Lunar Client-inspired JVM optimizations
        custom_jvm_args = [
            "-XX:+UseG1GC",
            "-XX:MaxGCPauseMillis=50",
            "-XX:+UnlockExperimentalVMOptions",
            "-XX:G1NewSizePercent=20",
            "-XX:G1ReservePercent=20",
            "-XX:G1HeapRegionSize=32M"
        ]

        cmd = [java_path] + custom_jvm_args + [f"-Xmx{ram}M", f"-Djava.library.path={natives_dir}", 
               "-cp", classpath, version_data["mainClass"]]

        # TLauncher-like offline mode
        game_args = [
            "--username", username,
            "--version", version,
            "--gameDir", ".",
            "--assetsDir", ASSETS_DIR,
            "--assetIndex", version_data["assets"],
            "--uuid", "00000000-0000-0000-0000-000000000000",
            "--accessToken", "0",
            "--userType", "legacy"
        ]
        cmd.extend(game_args)
        return cmd

    def launch_thread(self, version, username, ram="2048"):
        try:
            java_path = "java"
            if not self.download_version_files(version, self.versions[version]):
                raise Exception("Failed to download version files")
            cmd = self.build_launch_command(version, username, ram, java_path)
            subprocess.Popen(cmd, cwd=".")
            print("Minecraft launched successfully!")
        except Exception as e:
            print(f"Launch failed: {e}")
            self.after(0, lambda: messagebox.showerror("Error", f"Launch failed: {e}"))

    def prepare_and_launch(self):
        version = self.version_var.get()
        username = self.username.get()
        if not version or version == "No versions":
            messagebox.showerror("Error", "Please select a valid version.")
            return
        if not username:
            messagebox.showerror("Error", "Please enter a username.")
            return
        threading.Thread(target=self.launch_thread, args=(version, username), daemon=True).start()

if __name__ == "__main__":
    app = MinecraftLauncher()
    app.mainloop()
