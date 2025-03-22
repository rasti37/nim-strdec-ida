# strdec - IDAPython tool for Nim string literal decryption

strdec is an IDAPython tool for automatic decryption of string literals, encrypted with the Nim's module `strenc`.

## 📓 About

This python tool decrypts all the string literals inside the loaded binary. The `strenc` module encrypts the string literalls with simple XOR encryption so one can re-apply the encryption to decrypt the strings. For many literals, it can be annoying to do manually so that's why I made this automation tool.

> [!NOTE]
> 
> The script modifies the database by setting a comment with the decrypted string literal.

## 🎞️ Demonstration

<center><img src="demonstration.gif" /></center>

## 🚧 How to use

1. Load the binary in IDA Pro.

2. Go to `File > Script file...` or hit `Alt+F7` and load the script `strdec.py`.

3. Done.

> [!IMPORTANT]
>
> Make sure you do not rename the strenc symbol. By default, it should contain the identifier `gkkaekgaEE`. If the symbols are stripped, you will have to find the function yourself and give it a name that contains this identifier. Then the tool should work normally.

## 📝 Notes

- Only `PE` and `ELF` binaries are currently supported
- strdec has been tested with IDA Pro 7.6