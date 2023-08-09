import os

file_list = os.listdir('./')
file_list.remove('lines-to-stringarray.py')
if 'static-lists.go' in file_list:
    file_list.remove('static-lists.go')

go_file = open('static-lists.go', 'a')

lines = ["package cachesnake", "\n"]

for file in file_list:
    list_lines = open(file).read().splitlines()
    line = "var " + ''.join([cap.capitalize() for cap in file.split('.')[0].split('-')]) + " [{0}]string = [{0}]string{{".format(len(list_lines))
    for list_line in list_lines:
        line += ' "{}",'.format(list_line)
    line = line[:-1] + ' }\n'

    lines.append(line)
    lines.append("\n")

go_file.writelines(lines)