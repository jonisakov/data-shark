import bs4

class ReportEngine:

    def __init__(self):
        self._attack_report_list = list()
        self._template_path = '.\\report.html'
        self._tag_class_dict = {'not_detected': 'test-result-step-result-cell-ok', 'detected': 'test-result-step-result-cell-failure'}

    def _add_report_row(self, attack_definition, attack_description, attack_status):
        self._attack_report_list.append({'attack_definition': attack_definition, 'attack_description': attack_description, 'attack_status': attack_status})
    
    def _generate_report(self, path):
        # load the file
        with open(self._template_path) as inf:
            txt = inf.read()
            soup = bs4.BeautifulSoup(txt, 'html.parser')
        
        # table = soup.select('tbody')

        for attack in self._attack_report_list:
            attack_row = soup.new_tag('tr')

            new_td = soup.new_tag('td', )
            new_td.append(attack['attack_definition'])
            attack_row.append(new_td)
            soup.tbody.append(attack_row)

            new_td = soup.new_tag('td')
            new_td.append(attack['attack_description'])
            attack_row.append(new_td)
            soup.tbody.append(attack_row)

            new_td = soup.new_tag('td', **{'class': self._tag_class_dict[attack['attack_status']]})
            new_td.append(attack['attack_status'])
            attack_row.append(new_td)
            soup.tbody.append(attack_row)

        with open(path, "w") as file:
            file.write(str(soup))
