import setuptools

with open("README.md", "r") as f:
    long_description = f.read()


setuptools.setup(
    name='connectapi-core',
    packages=setuptools.find_packages(),
    version='1.0.1',
    license='MIT',
    description="""Core SDK for the ConnectAPI ecosystem""",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='ConnectAPI',
    author_email='connectapi.org@gmail.com',
    maintainer='ConnectAPI',
    maintainer_email='connectapi.org@gmail.com',
    url='https://github.com/ConnectAPI/python-core-client',
    keywords=['connectapi', 'ConnectAPI', 'web', 'client', 'core'],
    install_requires=['requests'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Environment :: Web Environment',
        'Topic :: Software Development',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
