const handler = require('../handler');

test('token is valid for +/- ten minutes', () => {
    const nineMinutes = 540000;
    const now = Date.now();
    const nineMinutesFromNow = (now + nineMinutes).toString()
    const nineMinutesAgo = (now - nineMinutes).toString();
    expect(handler.validateToken(`Bearer ${nineMinutesFromNow}${nineMinutesFromNow}`)).toBe(true);
    expect(handler.validateToken(`Bearer ${nineMinutesAgo}${nineMinutesAgo}`)).toBe(true);
});

test('mac addresses with accepted formats are reversed correctly', () => {
    expect(handler.reverse([
            '00:A0:C9:14:C8:29',
            '00-A0-C9-14-C8-29',
            '00A0C914C829',
        ],
    )).toStrictEqual({
        'reversed-macs': [
            '29:C8:14:C9:A0:00',
            '29-C8-14-C9-A0-00',
            '29C814C9A000',
        ],
    });
});

test('mac addresses with unaccepted formats are reported', () => {
    expect(handler.reverse([
            '00:A0:C9:14:C8:29',
            '00-A0-C9-14-C8-29-00',
            '00A0C914C8290',
        ],
    )).toStrictEqual({
        'reversed-macs': [
            '29:C8:14:C9:A0:00',
        ],
        'error': [{
            'mac': '00-A0-C9-14-C8-29-00',
            'error': 'Invalid format.',
        }, {
            'mac': '00A0C914C8290',
            'error': 'Invalid format.',
        }],
    });
});