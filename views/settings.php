<?php

/**
 * Intrusion detection rule set view.
 *
 * @category   apps
 * @package    intrusion-detection
 * @subpackage views
 * @author     ClearFoundation <developer@clearfoundation.com>
 * @copyright  2011 ClearFoundation
 * @license    http://www.gnu.org/copyleft/gpl.html GNU General Public License version 3 or later
 * @link       http://www.clearfoundation.com/docs/developer/apps/intrusion_detection/
 */

///////////////////////////////////////////////////////////////////////////////
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.  
//  
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Load dependencies
///////////////////////////////////////////////////////////////////////////////

$this->load->library('intrusion_detection/Snort');

$this->lang->load('base');
$this->lang->load('intrusion_detection');

///////////////////////////////////////////////////////////////////////////////
// Buttons
///////////////////////////////////////////////////////////////////////////////

$buttons = array(form_submit_update('submit', 'high'));

///////////////////////////////////////////////////////////////////////////////
// Headers
///////////////////////////////////////////////////////////////////////////////

$headers = array(
    lang('intrusion_detection_rule_set_type'),
    lang('intrusion_detection_rule_set'),
    lang('base_description'),
    lang('intrusion_detection_rules'),
);

///////////////////////////////////////////////////////////////////////////////
// Items
///////////////////////////////////////////////////////////////////////////////

foreach ($rule_sets as $rule_set => $entry) {

    // Skip unsupported rules
    //-----------------------    

    if ($entry['type'] === \clearos\apps\intrusion_detection\Snort::TYPE_UNSUPPORTED)
        continue;

    $item['title'] = $rule_set;
    $item['name'] = 'rule_sets[' . $rule_set . ']';
    $item['state'] = $entry['active'];
    $item['details'] = array(
        $entry['type_description'],
        $rule_set,
        $entry['description'],
        $entry['count']
    );

    $items[] = $item;
}

///////////////////////////////////////////////////////////////////////////////
// List table
///////////////////////////////////////////////////////////////////////////////

$options['grouping'] = TRUE;

echo form_open('intrusion_detection');

echo list_table(
    lang('intrusion_detection_rule_sets'),
    $buttons,
    $headers,
    $items,
    $options
);

echo form_close();
