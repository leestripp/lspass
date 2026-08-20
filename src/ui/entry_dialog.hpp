#pragma once

#include "vault.hpp"
#include "generator.hpp"
#include <gtkmm.h>

/// Modal create/edit dialog for a vault entry.
class EntryDialog : public Gtk::Window {
public:
    EntryDialog(Gtk::Window& parent, lspass::Entry entry, bool is_new,
                const lspass::PasswordOptions& gen_opts,
                sigc::slot<void(lspass::Entry)> on_save);

private:
    void on_save();
    void on_generate_secret();

    lspass::Entry entry_;
    lspass::PasswordOptions gen_opts_;
    bool is_new_;
    sigc::slot<void(lspass::Entry)> on_save_;

    Gtk::DropDown     type_;
    Gtk::Entry        title_, username_, url_;
    Gtk::PasswordEntry secret_;
    Gtk::TextView     notes_;
    Gtk::Label        error_;
};
