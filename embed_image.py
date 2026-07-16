import base64

def main():
    print("Reading starry-night.png...")
    with open('starry-night.png', 'rb') as f:
        img_data = f.read()
    b64_str = base64.b64encode(img_data).decode('utf-8')
    data_uri = f"url('data:image/png;base64,{b64_str}')"
    
    files = ['index.html', 'otp.html', 'signup.html']
    
    for filename in files:
        print(f"Processing {filename}...")
        with open(filename, 'r', encoding='utf-8') as f:
            html = f.read()
        
        target = "url('starry-night.png')"
        if target in html:
            html = html.replace(target, data_uri)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)
            print(f"Successfully embedded image in {filename}!")
        else:
            print(f"Target placeholder not found in {filename} (already embedded or missing).")

if __name__ == '__main__':
    main()
