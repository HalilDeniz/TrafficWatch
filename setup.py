from setuptools import setup, find_packages

setup(
    name='TrafficWatch',
    version='1.0.0',
    author='Halil Deniz',
    author_email='halildeniz313@gmail.com',
    url='https://github.com/HalilDeniz/TrafficWatch',
    description='A powerful packet sniffer and analysis tool',
    long_description=open('Readme.md', 'r').read(),
    long_description_content_type='text/markdown',
    packages=find_packages(),
    install_requires=[
        # List your dependencies here
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    entry_points={
        'console_scripts': [
            'trafficwatch = app.trafficwatch:main'
        ]
    },
)