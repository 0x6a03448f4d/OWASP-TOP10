#!/usr/bin/env python3
"""
Generate HTML documentation from markdown files for OWASP labs
"""
import os
import re
from pathlib import Path

def markdown_to_html(md_content, title):
    """Convert markdown to HTML with green theme styling"""
    
    # HTML template with green theme
    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="stylesheet" href="../../src/web-assets/dashboard.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .doc-container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        
        .back-nav {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            margin-bottom: 30px;
            color: var(--primary-color);
            text-decoration: none;
            border: 1px solid var(--border-color);
            border-radius: 5px;
            transition: all 0.3s;
        }}
        
        .back-nav:hover {{
            background-color: rgba(0, 255, 65, 0.1);
            border-color: var(--primary-color);
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
        }}
        
        .content {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 40px;
            border: 1px solid var(--border-color);
            box-shadow: 0 2px 10px rgba(0, 255, 65, 0.1);
        }}
        
        .content h1 {{
            color: var(--primary-color);
            font-size: 2.5rem;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid var(--primary-color);
            text-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
        }}
        
        .content h2 {{
            color: var(--secondary-color);
            font-size: 1.8rem;
            margin-top: 40px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .content h3 {{
            color: var(--primary-color);
            font-size: 1.4rem;
            margin-top: 30px;
            margin-bottom: 12px;
        }}
        
        .content h4 {{
            color: var(--secondary-color);
            font-size: 1.2rem;
            margin-top: 25px;
            margin-bottom: 10px;
        }}
        
        .content p {{
            color: var(--text-color);
            line-height: 1.8;
            margin-bottom: 15px;
        }}
        
        .content ul, .content ol {{
            margin-left: 25px;
            margin-bottom: 15px;
            color: var(--text-color);
        }}
        
        .content li {{
            margin-bottom: 10px;
            line-height: 1.6;
        }}
        
        .content code {{
            background: rgba(0, 0, 0, 0.3);
            padding: 2px 8px;
            border-radius: 4px;
            color: var(--primary-color);
            font-family: 'Courier New', monospace;
            border: 1px solid var(--border-color);
        }}
        
        .content pre {{
            background: rgba(0, 0, 0, 0.4);
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            margin: 20px 0;
            border: 1px solid var(--primary-color);
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.2);
        }}
        
        .content pre code {{
            background: none;
            padding: 0;
            border: none;
            color: var(--primary-color);
        }}
        
        .content blockquote {{
            border-left: 4px solid var(--primary-color);
            padding-left: 20px;
            margin: 20px 0;
            background: rgba(0, 255, 65, 0.05);
            padding: 15px 20px;
            border-radius: 4px;
        }}
        
        .content table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            border: 1px solid var(--border-color);
        }}
        
        .content table th {{
            background: linear-gradient(135deg, rgba(0, 255, 65, 0.2), rgba(13, 255, 146, 0.2));
            color: var(--primary-color);
            padding: 12px;
            text-align: left;
            border: 1px solid var(--border-color);
        }}
        
        .content table td {{
            padding: 12px;
            border: 1px solid var(--border-color);
            color: var(--text-color);
        }}
        
        .content table tr:hover {{
            background: rgba(0, 255, 65, 0.05);
        }}
        
        .content a {{
            color: var(--secondary-color);
            text-decoration: none;
            border-bottom: 1px solid transparent;
            transition: all 0.3s;
        }}
        
        .content a:hover {{
            color: var(--primary-color);
            border-bottom-color: var(--primary-color);
        }}
        
        .content strong {{
            color: var(--secondary-color);
            font-weight: 600;
        }}
        
        .toc {{
            background: rgba(0, 255, 65, 0.05);
            border: 1px solid var(--primary-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }}
        
        .toc h2 {{
            color: var(--primary-color);
            margin-top: 0;
            border-bottom: 2px solid var(--primary-color);
            padding-bottom: 10px;
        }}
        
        .toc ul {{
            list-style: none;
            margin-left: 0;
        }}
        
        .toc li {{
            margin-bottom: 8px;
        }}
        
        .toc a {{
            color: var(--text-color);
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .toc a:hover {{
            color: var(--primary-color);
        }}
        
        .toc a:before {{
            content: "▸";
            color: var(--primary-color);
        }}
    </style>
</head>
<body>
    <div class="doc-container">
        <a href="../../owasp-labs.html" class="back-nav">
            <i class="fas fa-arrow-left"></i> Back to Labs
        </a>
        
        <div class="content">
            CONTENT_PLACEHOLDER
        </div>
    </div>
</body>
</html>"""
    
    # Convert markdown to HTML
    html_content = md_content
    
    # Convert headers
    html_content = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^#### (.+)$', r'<h4>\1</h4>', html_content, flags=re.MULTILINE)
    
    # Convert bold and italic
    html_content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_content)
    html_content = re.sub(r'\*(.+?)\*', r'<em>\1</em>', html_content)
    
    # Convert inline code
    html_content = re.sub(r'`([^`]+)`', r'<code>\1</code>', html_content)
    
    # Convert code blocks
    html_content = re.sub(r'```([^\n]*)\n(.*?)```', r'<pre><code>\2</code></pre>', html_content, flags=re.DOTALL)
    
    # Convert links
    html_content = re.sub(r'\[([^\]]+)\]\(([^\)]+)\)', r'<a href="\2">\1</a>', html_content)
    
    # Convert lists
    lines = html_content.split('\n')
    in_ul = False
    in_ol = False
    result = []
    
    for line in lines:
        stripped = line.strip()
        
        # Unordered list
        if stripped.startswith('- ') or stripped.startswith('* '):
            if not in_ul:
                result.append('<ul>')
                in_ul = True
            result.append(f'<li>{stripped[2:]}</li>')
        # Ordered list
        elif re.match(r'^\d+\.\s', stripped):
            if not in_ol:
                result.append('<ol>')
                in_ol = True
            result.append(f'<li>{re.sub(r"^\d+\.\s", "", stripped)}</li>')
        else:
            if in_ul:
                result.append('</ul>')
                in_ul = False
            if in_ol:
                result.append('</ol>')
                in_ol = False
            result.append(line)
    
    if in_ul:
        result.append('</ul>')
    if in_ol:
        result.append('</ol>')
    
    html_content = '\n'.join(result)
    
    # Wrap paragraphs
    lines = html_content.split('\n')
    result = []
    in_tag = False
    
    for line in lines:
        stripped = line.strip()
        if not stripped:
            result.append(line)
            continue
            
        if stripped.startswith('<') and (
            stripped.startswith('<h') or 
            stripped.startswith('<ul') or 
            stripped.startswith('<ol') or 
            stripped.startswith('<pre') or 
            stripped.startswith('<blockquote') or
            stripped.startswith('<table') or
            stripped.startswith('</') or
            stripped.startswith('<li')
        ):
            result.append(line)
        else:
            if stripped and not stripped.startswith('<'):
                result.append(f'<p>{line}</p>')
            else:
                result.append(line)
    
    html_content = '\n'.join(result)
    
    return html_template.replace('CONTENT_PLACEHOLDER', html_content)


def process_lab_directory(lab_dir):
    """Process all markdown files in a lab directory"""
    print(f"Processing {lab_dir}...")
    
    md_files = ['overview.md', 'prevention.md', 'attack-vectors.md', 'examples.md']
    
    for md_file in md_files:
        md_path = lab_dir / md_file
        if md_path.exists():
            # Read markdown
            with open(md_path, 'r', encoding='utf-8') as f:
                md_content = f.read()
            
            # Get title from first line
            title_match = re.match(r'^# (.+)$', md_content, re.MULTILINE)
            title = title_match.group(1) if title_match else md_file.replace('.md', '').title()
            
            # Convert to HTML
            html_content = markdown_to_html(md_content, title)
            
            # Write HTML file
            html_file = md_path.with_suffix('.html')
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"  Created {html_file.name}")


def main():
    """Process all OWASP lab directories"""
    base_dir = Path(__file__).parent
    
    # Find all lab directories
    lab_categories = ['OWASP-Web', 'OWASP-API', 'OWASP-Mobile', 'OWASP-LLM']
    
    for category in lab_categories:
        category_dir = base_dir / category
        if not category_dir.exists():
            continue
        
        print(f"\n=== Processing {category} ===")
        
        # Process each lab in the category
        for lab_dir in sorted(category_dir.iterdir()):
            if lab_dir.is_dir() and not lab_dir.name.startswith('.'):
                process_lab_directory(lab_dir)
    
    print("\n✅ All documentation HTML files generated!")


if __name__ == '__main__':
    main()
