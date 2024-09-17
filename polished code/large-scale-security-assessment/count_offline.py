import json, sys

protocol = sys.argv[1]

ENDPOINTS_2023 = json.load(open(protocol + '_diff_2023.json', 'r'))
ENDPOINTS_2024 = json.load(open(protocol + '_diff_2024.json', 'r'))

def count_offline(file, year):
    count_total = 0
    count_offline = 0

    for backend, val in file.items():
        count_total += 1

        if year == '2023':
            if val['status_sep_2023'] == 'offline':
                count_offline += 1
        else:
            if val['status_jan2024'] == 'offline':
                count_offline += 1


    # print(count_total)
    print('Protocol analyzed: ', protocol)
    print("Offline in ", year, ':', count_offline, '(', (count_offline)*100/count_total, '%)')
    # print((count_offline)*100/count_total)

count_offline(ENDPOINTS_2023, '2023')
count_offline(ENDPOINTS_2024, '2024')
