package com.quarkslab.quokka.utils;

import ghidra.app.util.Option;
import docking.widgets.button.GRadioButton;
import java.awt.Component;
import java.awt.FlowLayout;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JPanel;

public class EnumOption extends Option {
    /**
     * Construct a new EnumOption.
     * 
     * @param name name of the option
     * @param value value of the option. Value can't be null with this constructor.
     * @throws IllegalArgumentException if value is null
     */
    public EnumOption(String name, Object value) {
        super(name, value);
    }

    /**
     * Construct a new EnumOption.
     * 
     * @param group Name for group of options
     * @param name name of the option
     * @param value value of the option
     * @throws IllegalArgumentException if value is null
     */
    public EnumOption(String group, String name, Object value) {
        super(group, name, value);
    }

    /**
     * Construct a new EnumOption.
     * 
     * @param name name of the option
     * @param valueClass class of the option's value
     *
     */
    public EnumOption(String name, Class<?> valueClass) {
        super(name, valueClass);
    }

    /**
     * Construct a new EnumOption
     * 
     * @param name name of the option
     * @param value value of the option
     * @param valueClass class of the option's value
     * @param arg the option's command line argument
     *
     */
    public EnumOption(String name, Object value, Class<?> valueClass, String arg) {
        super(name, value, valueClass, arg);
    }

    /**
     * Construct a new EnumOption
     *
     * @param name name of the option
     * @param valueClass class of the option's value
     * @param value value of the option
     * @param arg the option's command line argument
     * @param group Name for group of options
     */
    public EnumOption(String name, Class<?> valueClass, Object value, String arg, String group) {
        super(name, valueClass, value, arg, group);
    }

    @Override
    public EnumOption copy() {
        return new EnumOption(this.getName(), this.getValueClass(), this.getValue(), this.getArg(),
                this.getGroup());
    }

    @Override
    public Component getCustomEditorComponent() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        ButtonGroup group = new ButtonGroup();

        // Create all the buttons
        for (final var enumValue : this.getValueClass().getEnumConstants()) {
            GRadioButton button = new GRadioButton(enumValue.toString());
            boolean initialState = enumValue == this.getValue() ? true : false;
            button.setSelected(initialState);
            group.add(button);
            panel.add(button);
            button.addItemListener(e -> {
                if (button.isSelected())
                    this.setValue(enumValue);
            });
        }

        return panel;
    }
}
