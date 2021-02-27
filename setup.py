
import setuptools

setuptools.setup(
    name='fastapi-auth0',
    version='0.1.3',
    author='Dorin Clisu',
    author_email='dorin.clisu@gmail.com',
    packages=setuptools.find_packages('src'),
    license='GNU-GPL-V3',
    description='Easy auth0.com integration for FastAPI',
    python_requires='>=3.6',
    install_requires=['fastapi>=0.60.0', 'python-jose>=3.2.0', 'requests']
)
