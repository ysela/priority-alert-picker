from itertools import islice


class AlertPriorities:
    templates = {
        1: [
            {
                'alert_type': 'AttackIndication',
                'alert_subtype': 'BlackMarket',
                'title_identifiers': [
                    'A bot server holding company customer credentials is offered for sale on a BlackMarket',
                ],
            },
            {
                'alert_type': 'AttackIndication',
                'alert_subtype': 'BotDataForSale',
                'title_identifiers': [
                    'A bot server with credentials for a company',
                    'employees login credentials',
                ],
            },
        ],
        2: [
            {
                'alert_type': 'DataLeakage',
                'alert_subtype': 'ConfidentialInformationExposed',
                'title_identifiers': [
                    'GitHub',
                ],
            },
        ],
        3: [
            {
                'alert_type': 'DataLeakage',
                'alert_subtype': 'CredentialsLeakage',
                'title_identifiers': [
                    'login credentials of',
                    'were leaked',
                ],
            },
            {
                'alert_type': 'DataLeakage',
                'alert_subtype': 'CredentialsLeakage',
                'title_identifiers': [
                    'Company DB is offered for',
                ],
            },
        ],
        4: [
            {
                'alert_type': 'DataLeakage',
                'alert_subtype': 'ConfidentialDocumentLeakage',
                'title_identifiers': [
                    'A company\'s confidential document was exposed publicly',
                ],
                'source_identifiers': [
                    'virustotal.com',
                ],
            },
        ],
        5: [
            {
                'alert_type': 'VIP',
                'alert_subtype': 'BlackMarket',
                'title_identifiers': [
                    'VIP - Private details of a company VIP are offered for sale on a black market',
                ],
            },
        ],
        6: [
            {
                'alert_type': 'DataLeakage',
                'alert_subtype': 'ExposedMentionsOnGithub',
                'title_identifiers': [
                    'GitHub',
                ],
            },
        ],
    }

    alerts = [
        # matches priority 4
        {
            '_id': '000000001',
            'Title': 'A company\'s confidential document was exposed publicly',
            'Details': {
                'Type': 'DataLeakage',
                'SubType': 'ConfidentialDocumentLeakage'
            }
        },
        # matches priority 1
        {
            '_id': '000000002',
            'Title': 'A bot server with credentials for a company',
            'Details': {
                'Type': 'AttackIndication',
                'SubType': 'BotDataForSale'
            }
        },
        # matches priority 1
        {
            '_id': '000000003',
            'Title': 'A bot server holding company customer credentials is offered for sale on a BlackMarket',
            'Details': {
                'Type': 'AttackIndication',
                'SubType': 'BlackMarket',
            },
        },
        # purposely matches priority 5
        {
            '_id': '000000004',
            'Title': 'VIP - Private details of a company VIP are offered for sale on a black market',
            'Details': {
                'Type': 'VIP',
                'SubType': 'BlackMarket',
            }
        },
        # purposely matches one of priority 3
        {
            '_id': '000000005',
            'Title': 'Company DB is offered for a ton of money',
            'Details': {
                'Type': 'DataLeakage',
                'SubType': 'CredentialsLeakage',
            }
        },
        # purposely matches priority 2
        {
            '_id': '000000006',
            'Title': 'GitHub has an error',
            'Details': {
                'Type': 'DataLeakage',
                'SubType': 'ConfidentialInformationExposed',
            }
        },
    ]

# O(n) complexity


def check_title_match(alert_title, identifiers):
    if any(map(alert_title.__contains__, identifiers)):
        return True


def find_priority_alerts(alerts):
    prioritized_alerts = {}
    for alert in alerts:
        for priority_level in AlertPriorities.templates:
            if not prioritized_alerts.get(priority_level):
                prioritized_alerts[priority_level] = []
            for template in AlertPriorities.templates[priority_level]:
                is_type_match = template['alert_type'] == alert['Details']['Type']
                is_subtype_match = template['alert_subtype'] == alert['Details']['SubType']
                is_title_match = check_title_match(
                    alert_title=alert['Title'], identifiers=template['title_identifiers'])
                if is_type_match and is_subtype_match and is_title_match:
                    prioritized_alerts[priority_level].append(alert)
    gen = (val['_id'] for sub_list in prioritized_alerts.values()
           for val in sub_list)
    return list(islice(gen, 4))


find_priority_alerts(AlertPriorities.alerts)
