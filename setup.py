import setuptools

BASE_REQUIREMENTS = [
    'makefun==1.9.5', 'PyJWT==2.0.0', 
    'python-jwt==3.3.0', 'fastapi', 
    'uvicorn', 'python-multipart==0.0.5', 
    'easyadmin==0.136', 'easyrpc>=0.241',
    
]
SERVER_REQUIREMENTS = [
    'aiopyql>=0.357', 'cryptography', 
    'bcrypt==3.2.0', 'uvloop', 
    'example', 'httptools',
    'gunicorn', 'fastapi-mail==0.3.7'
    ]
CLIENT_REQUIREMENTS = []

with open("README.md", "r") as fh:
    long_description = fh.read()
setuptools.setup(
     name='easy-auth',  
     version='NEXTVERSION',
     packages=setuptools.find_packages(include=['easyauth'], exclude=['build']),
     author="Joshua Jamison",
     author_email="joshjamison1@gmail.com",
     description="Create a centralized Authentication and Authorization token server. Easily secure FastAPI endpoints based on Users, Groups, Roles or Permissions with very little database usage.",
     long_description=long_description,
   long_description_content_type="text/markdown",
     url="https://github.com/codemation/easyauth",
     classifiers=[
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: MIT License",
         "Operating System :: OS Independent",
     ],
     python_requires='>=3.7, <4',   
     install_requires=BASE_REQUIREMENTS,
     extras_require={
         'all': SERVER_REQUIREMENTS,
         'server': SERVER_REQUIREMENTS,
         'client': CLIENT_REQUIREMENTS
     }
 )