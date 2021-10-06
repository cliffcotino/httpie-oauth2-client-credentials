from setuptools import setup

setup(
    name="httpie-oauth2-client-credentials",
    description="httpie auth plugin for OAuth2.0 client credentials flow.",
    version="0.1.0",
    author='satdoc',
    author_email='satodoc-develop-public@outlook.com',
    url='https://github.com/satodoc/httpie-oauth2-client-credentials',
    download_url='https://github.com/satodoc/httpie-oauth2-client-credentials',
    py_modules=['httpie_oauth2_client_credentials'],
    install_requires=['httpie>=2.0.0'],
    entry_points={
        'httpie.plugins.auth.v1': [
            'httpie_oauth2_client_credentials = httpie_oauth2_client_credentials:OAuth2ClientCredentialsPlugin'
        ]
    }
)
