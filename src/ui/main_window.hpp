#pragma once

#include "vault.hpp"
#include "generator.hpp"
#include <gtkmm.h>
#include <optional>

class MainWindow : public Gtk::ApplicationWindow {
public:
    MainWindow();

private:
    // locked page
    void on_unlock_clicked();
    void show_lock_error(const Glib::ustring& msg);
    // unlocked page
    void refresh_entries(const Glib::ustring& filter = {});
    void on_lock();
    void on_add(int type);
    void on_edit(const lspass::Entry& e);
    void on_delete(const lspass::Entry& e);
    void on_change_master();
    void on_settings();
    void load_settings();
    void copy_to_clipboard(const std::string& text, bool sensitive);
    void show_toast(const Glib::ustring& msg);

    static std::string vault_path();

    std::optional<lspass::Vault> vault_;
    lspass::PasswordOptions      gen_opts_;
    bool creating_ = false;

    Gtk::Stack        stack_;
    Gtk::Box          root_box_{Gtk::Orientation::VERTICAL, 0};
    Gtk::Label        status_;
    guint             status_timeout_ = 0;

    // locked page widgets
    Gtk::Box           locked_box_{Gtk::Orientation::VERTICAL, 12};
    Gtk::Label         lock_title_, lock_status_;
    Gtk::PasswordEntry pw_entry_, pw_confirm_;
    Gtk::Button        unlock_btn_{"Unlock"};

    // unlocked page widgets
    Gtk::Box            unlocked_box_{Gtk::Orientation::VERTICAL, 8};
    Gtk::SearchEntry    search_;
    Gtk::ScrolledWindow scroll_;
    Gtk::ListBox        list_;
    Gtk::Label          empty_label_{"No entries yet. Add one below."};
};
