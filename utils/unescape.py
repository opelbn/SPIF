import sys

if len(sys.argv) > 1:
    # Read from the specified file
    input_source = sys.argv[1]
    with open(input_source, 'r', encoding='utf-8') as file:
        content = file.read()
else:
    # Check if stdin is redirected or if the script is run without input
    if sys.stdin.isatty():
        print("Usage: python script.py [input_file]")
        print("If no input_file is provided, reads from stdin.")
        sys.exit(1)
    # Read from stdin
    content = sys.stdin.read()

# Remove all backslash characters
content = content.replace('\\', '')

# Write the result to readme.md
with open('C:/Users/benja/Projects/SPIF/README.md', 'w', encoding='utf-8') as file:
    file.write(content)