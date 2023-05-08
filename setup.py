from setuptools import setup

setup(
    name="httpie-oauth2-client-credentials",
    description="httpie auth plugin for OAuth2.0 client credentials flow.",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    version="0.1.2",
    author='satdoc',
    author_email='satodoc-develop-public@outlook.com',
    license='MIT',
    url='https://github.com/satodoc/httpie-oauth2-client-credentials',
    download_url='https://github.com/satodoc/httpie-oauth2-client-credentials',
    py_modules=['httpie_oauth2_client_credentials'],
    install_requires=['httpie>=2.0.0'],
    entry_points={
        'httpie.plugins.auth.v1': [
            'httpie_oauth2_client_credentials = httpie_oauth2_client_credentials:OAuth2ClientCredentialsPlugin'
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python',
        'Intended Audience :: Developers',
        'Environment :: Console',
        'Environment :: Plugins',
        'License :: OSI Approved :: MIT License',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Utilities'
    ],
)
