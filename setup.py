from setuptools import setup, find_packages

setup(
    name='AICaretaker',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[], 
    entry_points={
 
    },
    author='Grzegorz Dostatni',
    author_email='gregdostatni@gmail.com',
    description='Technology demonstrator self-adapting code',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/greg-d128/caretaker',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
