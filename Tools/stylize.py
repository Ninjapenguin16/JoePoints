import subprocess
import sys

def merge_multiline_function(lines):
    """
    Merge multi-line function definitions into a single line based on matching parentheses.
    Preserve empty lines.
    """
    output = []
    buffer = ""
    open_parens = 0

    for line in lines:
        stripped_line = line.rstrip('\n')

        # Skip empty lines from buffering
        if not stripped_line:
            if buffer:
                buffer += " "  # keep buffer space
            else:
                output.append("")  # preserve empty line
            continue

        # Count parentheses
        open_parens += stripped_line.count('(')
        open_parens -= stripped_line.count(')')

        if buffer:
            buffer += " " + stripped_line.strip()
        else:
            buffer = stripped_line.strip()

        if open_parens <= 0 and buffer:
            output.append(buffer)
            buffer = ""
            open_parens = 0

    # Append any leftover buffer
    if buffer:
        output.append(buffer)

    return output

def insert_blank_line_before_return(lines):
    """
    Insert an empty line before each return statement if the previous line is not empty.
    Preserve all existing blank lines.
    """
    output = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('return') and output and output[-1].strip() != '':
            output.append('')  # blank line before return
        output.append(line)
    return output

def main():
    if len(sys.argv) != 2:
        print("Usage: python stylize.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]

    # Step 1: Run clang-format in-place first to normalize spacing
    subprocess.run(['clang-format', '-i', filename], check=True)

    # Step 2: Read file
    with open(filename, 'r') as f:
        lines = f.readlines()

    # Step 3: Merge multi-line function definitions
    merged_lines = merge_multiline_function(lines)

    # Step 4: Insert blank line before return statements
    final_lines = insert_blank_line_before_return(merged_lines)

    # Step 5: Write back to file
    with open(filename, 'w') as f:
        for line in final_lines:
            f.write(line + '\n')

    # Step 6: Run clang-format again to fix indentation
    subprocess.run(['clang-format', '-i', filename], check=True)

if __name__ == "__main__":
    main()
