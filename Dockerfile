FROM python:3
ADD server_bottle.py /
RUN pip3 install bottle pycryptodomex 
CMD [ "python3", "./server_bottle.py" ]