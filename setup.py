from setuptools import setup, find_packages

setup(
    name="network-scanner",
    version="2.0.0",
    packages=find_packages(),
    install_requires=[
        # Core networking
        "scapy>=2.5.0",
        "python-nmap>=0.7.1",
        "manuf>=1.1.5",  # MAC vendor lookup
        
        # Security analysis
        "pyp0f>=0.3.0",  # Passive OS fingerprinting
        "pyOpenSSL>=23.2.0",  # SSL analysis
        "packaging>=23.1",  # Version comparison for CVEs
        
        # Data processing
        "pandas>=2.0.3",
        "dpkt>=1.9.8",  # Packet analysis
        "numpy>=1.24.0",  # ML features
        
        # Machine Learning
        "scikit-learn>=1.3.0",
        "joblib>=1.2.0",  # Model persistence
        
        # Visualization & UI
        "rich>=13.7.0",
        "plotly>=5.15.0",  # Dashboard
        "dash>=2.11.0",
        
        # WiFi scanning
        "wireless>=0.3.2",  # Cross-platform WiFi
        "netifaces>=0.11.0",  # Interface detection
    ],
    extras_require={
        'full': [
            "gpu-cv>=1.0.0",  # For advanced image analysis (IoT devices)
            "tensorflow>=2.12.0",  # Deep learning classifiers
        ],
        'dev': [
            "pytest>=7.4.0",
            "black>=23.7.0",
            "mypy>=1.5.0",
        ]
    },
    entry_points={
        'console_scripts': [
            'net-scanner=network_scanner.cli:main',
        ],
    },
    package_data={
        'scanner': [
            'ml/model.pkl',  # Include pre-trained model
            'utils/oui.txt',  # MAC vendor DB
            'utils/cve_db.json',  # CVE database
        ],
    },
    python_requires='>=3.9',
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
)
# pip install rich requests python-nmap scapy