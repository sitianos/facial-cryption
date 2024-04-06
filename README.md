This project is part of "[OpenCV/OpenGLによる映像処理](https://nae-lab.org/lecture/OpenCV+OpenGL/)", A semester experiment for 3rd-year EEIC students.

# Facial Cryption
The goal of this project is to encrypt or decrypt files including images with your face as a key.
In general, a device which supports face authentication utilizes a vector extracted from human face.
It extracts a vector from user's face detected through its camera, and compares it with a vector which was saved in advance.
Based on the similarity between them, it determines whether the user is authenticated.
But two vectors rarely match completely even if they are extracted from the same user's face because of several factors such as the angle of camera.
These factors make it difficult to create a key for encryption and decryption because it must be a specific value.

To deal with this difiiculty this application focused on LSH (locality sensitive hashing), which makes it possible to extract the same value from similar vector with high probability.
This application first extacts a vector from face in the same way as face authentication and then generates a key with LSH.
Threfore if two faces are similar and two extracted vectors are too, they are likely to create the same key.
And the extent to which similar vectors create the same value is called sensitivity.
High sensitivity makes the key longer (more secure in other word) but also makes the application less likely to generate the same key from the same user's face.
And low sensitivity allows application to easily generate the same key from the same user but also from a different user in bad case.
So it is important to consider the balance between security and convenience, and configure the sensitivity properly.

# Prerequisite
- OpenCV
- libpng 
- libssl (>=3.0)
- pkg-config

# Build
The following commands build the application and create executable `bin/facial_cryption`
```
git clone git@github.com:sitianos/facial-cryption.git
cd facial-cryption
make
```

# Usage
The following command shows available options.
```
./bin/facial_cryption -h
```

For example, you can encrypt an image file with your face through a built-in camera by
```
./bin/facial_cryption -i image.png -o encrypted.png -e
```
and decrypt it with your face by
```
./bin/facial_cryption -i encrypted.png -o decrypted.png -d
```
