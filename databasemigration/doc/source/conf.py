# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'eIDAS Middleware Migration Guide'
copyright = '2024, Governikus'
author = 'Governikus'
release = '3.3.0'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = []

templates_path = ['_templates']
exclude_patterns = []

master_doc = 'index'


# -- Options for LaTeX output ---------------------------------------------

latex_elements = {
    # The paper size ('letterpaper' or 'a4paper').
    'papersize': 'a4paper',

    # The font size ('10pt', '11pt' or '12pt').
    'pointsize': '11pt',

    # Additional stuff for the LaTeX preamble.

    'fncychap': r'\usepackage[Bjornstrup]{fncychap}',
    'printindex': r'\footnotesize\raggedright\printindex',
    'preamble': r'''
\let\cleardoublepage\clearpage
\usepackage{fancyhdr}
\pagestyle{fancy}
\fancyfoot{}
\fancyfoot[LE,RO]{\thepage}
\fancypagestyle{plain}{%
  \fancyhead{}%
  \renewcommand*{\headrule}{}%
  \fancyfoot{}%
  \fancyfoot[RE,RO]{\thepage}%
}
\hypersetup{pdfauthor={Governikus GmbH \& Co. KG},
            pdftitle={eIDAS Middleware Migration Guide},
            pdfsubject={eIDAS Middleware Migration Guide},
            pdfkeywords={manual, howto, documentation, handbuch},
            pdfproducer={LaTeX},
            pdfcreator={Sphinx}
            }

''',

    # Override tableofcontents
    'tableofcontents': r'''
\tableofcontents
\newpage
\pagestyle{plain}
\pagenumbering{arabic}
''',

    # Latex figure (float) alignment
    'figure_align': 'H',

}
# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
    (master_doc, 'eIDASMiddlewareMigrationGuide.tex', u'eIDAS Middleware Migration Guide',
     u'Governikus GmbH \& Co. KG', 'manual'),
]

# For "manual" documents, if this is true, then toplevel headings are parts,
# not chapters.
latex_use_parts = True

# If true, show page references after internal links.
# latex_show_pagerefs = False

# If true, show URL addresses after external links.
latex_show_urls = "footnote"

# Documents to append as an appendix to all manuals.
# latex_appendices = []

# If false, no module index is generated.
# latex_domain_indices = True

# -- Options for Texinfo output -------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
    (master_doc, 'eIDASMiddlewareMigrationGuide', u'eIDAS Middleware Migration Guide',
     author, 'eIDASMiddleware', 'One line description of project.',
     'Miscellaneous'),
]

# Documents to append as an appendix to all manuals.
# texinfo_appendices = []

# If false, no module index is generated.
# texinfo_domain_indices = True

# How to display URL addresses: 'footnote', 'no', or 'inline'.
# texinfo_show_urls = 'footnote'

# If true, do not generate a @detailmenu in the "Top" node's menu.
# texinfo_no_detailmenu = False
