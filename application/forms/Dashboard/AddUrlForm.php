<?php
// {{{ICINGA_LICENSE_HEADER}}}
// {{{ICINGA_LICENSE_HEADER}}}

namespace Icinga\Form\Dashboard;

use Icinga\Application\Config as IcingaConfig;
use Icinga\Web\Widget\Dashboard;
use Icinga\Web\Form;

/**
 * Form to add an url a dashboard pane
 */
class AddUrlForm extends Form
{
    /**
     * @see Form::createElements()
     */
    public function createElements(array $formData)
    {
        $elements = array(
            $this->createElement(
                'text',
                'url',
                array(
                    'required'  => true,
                    'label'     => t('Url'),
                    'helptext'  => t('The url being loaded in the dashlet')
                )
            )
        );

        $paneSelectionValues = $this->getDashboardPaneSelectionValues();
        if (empty($paneSelectionValues) ||
            ((isset($formData['create_new_pane']) && $formData['create_new_pane'] != false) &&
             (false === isset($formData['use_existing_dashboard']) || $formData['use_existing_dashboard'] != true))
        ) {
            $elements[] = $this->createElement(
                'text',
                'pane',
                array(
                    'required'  => true,
                    'label'     => t("The New Pane's Title"),
                    'style'     => 'display: inline-block'
                )
            );
            $elements[] = $this->createElement( // Prevent the button from being displayed again on validation errors
                'hidden',
                'create_new_pane',
                array(
                    'value' => 1
                )
            );
            if (false === empty($paneSelectionValues)) {
                $elements[] = $this->createElement(
                    'submit',
                    'use_existing_dashboard',
                    array(
                        'ignore'    => true,
                        'label'     => t('Use An Existing Pane'),
                        'style'     => 'display: inline-block'
                    )
                );
            }
        } else {
            $elements[] = $this->createElement(
                'select',
                'pane',
                array(
                    'required'      => true,
                    'label'         => t('Pane'),
                    'style'         => 'display: inline-block;',
                    'multiOptions'  => $paneSelectionValues
                )
            );
            $elements[] = $this->createElement(
                'submit',
                'create_new_pane',
                array(
                    'ignore'    => true,
                    'label'     => t('Create A New Pane'),
                    'style'     => 'display: inline-block'
                )
            );
        }

        $elements[] = $this->createElement(
            'text',
            'component',
            array(
                'required'  => true,
                'label'     => t('Title'),
                'helptext'  => t('The title for the dashlet')
            )
        );
        return $elements;
    }

    /**
     * @see Form::addSubmitButton()
     */
    public function addSubmitButton()
    {
        $this->addElement(
            'submit',
            'btn_submit',
            array(
                'ignore'    => true,
                'label'     => t('Add To Dashboard')
            )
        );

        return $this;
    }

    /**
     * Return the names and titles of the available dashboard panes as key-value array
     *
     * @return  array
     */
    protected function getDashboardPaneSelectionValues()
    {
        $dashboard = new Dashboard();
        $dashboard->readConfig(IcingaConfig::app('dashboard/dashboard'));
        return $dashboard->getPaneKeyTitleArray();
    }
}
