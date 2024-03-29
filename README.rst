
UMTRI Image Annotation Tool
========

.. image:: https://img.shields.io/pypi/v/labelimg.svg
        :target: https://pypi.python.org/pypi/labelimg

.. image:: https://img.shields.io/travis/tzutalin/labelImg.svg
        :target: https://travis-ci.org/tzutalin/labelImg

.. image:: /resources/icons/full_logo.png
    :align: center


UMTRI Image Annotation Tool is adapted from LabelImg and is being developed and maintained by Shaun Luo. Special thanks to Tzutalin for his initial work. 

The UMTRI IAT is written in Python and uses PyQt5 for its GUI. It allows users to create drag and create bounding boxes and label them. 
Annotations are saved as XML files in PASCAL VOC format, the format used
by `ImageNet <http://www.image-net.org/>`__.  Besides, it also supports YOLO format

.. image:: /demo/demo3.png
    :align: center
^UMTRI IAT running on Lubuntu


.. image:: /demo/demo5.png
    :align: center
^UMTRI IAT running on Deepin


.. image:: /demo/demo8.png
    :align: center
^UMTRI IAT running on OSX Mojave

`Video Demo
</demo/video_demo.mp4>`_

`Quick Start Guide
<http://umtri.org/file/v0.3.pdf>`_

ATTENTION
------------------
Only Linux(Ubuntu, Debian, Deepin) and macOS are officially supported at this moment. Binaries for macOS and Windows is scheduled to be released at a later date. 


Configuration
------------------
The UMTRI Image Annotation Tool requires two components to work properly -- a server and a client.

The client retrieves data sets hosted on the server and sends the labels back during submit

The Server
~~~~~~~~~~~~~~~~~
• The server hosts the data sets to be labeled. Server infomation is entered during the client's startup. 

• The server must support SSH and SCP. 

• The server must contain a file called 'predefined_classes.txt' at the root directory. This text file contains predefined labels that the client will fetch. 

• The server must also contain three folders 'labeled', 'unlabeled' and 'labels'.

• The .zip files of the data sets are placed in the unlabeled folder. 

• The .zip files must be a folder of the same name when inflated and contains supported image files (jpg, jpeg, png） within this inflated folders.


The Client
~~~~~~~~~~~~~~~~~
• Clone this repo.
.. code:: shell

    git clone https://github.com/yuxluo/umtri_label.git

• Install prerequisites (including pip3, pyqt5, pyqt5-dev-tools, lxml, paramiko, scp. This action may require root privilege)
.. code:: shell

    ./install.sh
    
• or this if you are using a mac
.. code:: shell

    ./install_macOS.sh
    
• make and run 
.. code:: shell

    ./run.sh

Usage
-----

1. Build and launch using the instructions above
2. Enter your access code and server information. Ask the project instructor if you are not sure
3. Click 'Retrieve'
4. Click 'Create RectBox'
5. Click and release left mouse to select a region to annotate the rect box
6. Click 'Next' and repeat step 4 until reaching the end of the datase 
7. Click 'Submit'
8. Repeat step 3.

The annotation will be saved automatically when you click next or sumbit

You can refer to the below hotkeys to speed up your workflow.


Hotkeys
~~~~~~~

+------------+--------------------------------------------+
| Ctrl + u   | Load all of the images from a directory    |
+------------+--------------------------------------------+
| Ctrl + r   | Change the default annotation target dir   |
+------------+--------------------------------------------+
| Ctrl + s   | Save                                       |
+------------+--------------------------------------------+
| Ctrl + d   | Copy the current label and rect box        |
+------------+--------------------------------------------+
| Space      | Flag the current image as verified         |
+------------+--------------------------------------------+
| w          | Create a rect box                          |
+------------+--------------------------------------------+
| d          | Next image                                 |
+------------+--------------------------------------------+
| a          | Previous image                             |
+------------+--------------------------------------------+
| del        | Delete the selected rect box               |
+------------+--------------------------------------------+
| Ctrl++     | Zoom in                                    |
+------------+--------------------------------------------+
| Ctrl--     | Zoom out                                   |
+------------+--------------------------------------------+
| ↑→↓←       | Keyboard arrows to move selected rect box  |
+------------+--------------------------------------------+

**Verify Image:**

When pressing space, the user can flag the image as verified, a green background will appear.
This is used when creating a dataset automatically, the user can then through all the pictures and flag them instead of annotate them.

**Difficult:**

The difficult field is set to 1 indicates that the object has been annotated as "difficult", for example, an object which is clearly visible but difficult to recognize without substantial use of context.
According to your deep neural network implementation, you can include or exclude difficult objects during training.

**Hierarchy:**

Right click on the label and select 'add component' to add a child to the selected object. 


License
~~~~~~~
`Free software: MIT license <https://github.com/tzutalin/labelImg/blob/master/LICENSE>`_

Citation: Tzutalin. LabelImg. Git code (2015). https://github.com/tzutalin/labelImg

Changelog
-----
Alpha 0.1
~~~~~~~
• This ReadMe page
• logo and title bar
• Disclaimer
• Authentication
• Remote file server 
• Modern and consistent icons
• Progress bar
• Retrieve function
• Auto move .zip to labeled 
• Auto download .zip from server
• Auto download predefined_classes
• Auto unzip
• Auto load folder and predefined_classes
• Autosave when click next and Submit
• Submit function
• Auto compress labels into zip 
• Auto upload labels to server 
• Auto local clean up 
• Added preemptive checking in case unlabeled folder is empty or server unable to connect

Alpha 0.2
~~~~~~~
• New UI function, right click on label to add component 
• Auto-format & auto-fill in pop-up dialog
• Ordered label list -> parent on top, immediate children below 
• Modified data structure to allow ID and parent/child relation
• Post-processing: reflect hierarchy when outputing in pascal_voc format .XML
• Can read hierarchy from file into program while maintaining the correct odering

Alpha 0.3
~~~~~~~
• Moved from a list representation to a tree representation of labels
• More intuitive hierarchy on the user interface 
• Recursive label check
• Recursive delete 
• Reconstruction of tree when loading label from file
• Various bug fixes

Future Features
~~~~~~~
• ?
