#include "main_window.hpp"
#include "entry_dialog.hpp"

#include <glibmm/keyfile.h>
#include <glibmm/miscutils.h>

namespace {

std::string config_path() {
    return Glib::get_user_config_dir() + "/lspass/lspass.conf";
}

/// Dark is the default. The pref lives outside the (encrypted) vault so
/// it can be applied before unlock.
bool load_dark_pref() {
    auto kf = Glib::KeyFile::create();
    try {
        kf->load_from_file(config_path(), Glib::KeyFile::Flags::NONE);
        return kf->get_boolean("appearance", "dark");
    } catch (...) {
        return true; // default: dark mode
    }
}

void save_dark_pref(bool dark) {
    auto kf = Glib::KeyFile::create();
    try {
        kf->load_from_file(config_path(), Glib::KeyFile::Flags::NONE);
    } catch (...) { /* first run — start fresh */ }
    kf->set_boolean("appearance", "dark", dark);
    const auto path = config_path();
    gchar* dir = g_path_get_dirname(path.c_str());
    g_mkdir_with_parents(dir, 0700);
    g_free(dir);
    try {
        kf->save_to_file(path);
    } catch (...) { /* non-fatal: theme just won't persist */ }
}

void apply_theme(bool dark) {
    if (auto settings = Gtk::Settings::get_default())
        settings->property_gtk_application_prefer_dark_theme().set_value(dark);
}

} // namespace

MainWindow::MainWindow() {
    apply_theme(load_dark_pref());
    set_title("lsPass — Password Manager");
    set_default_size(600, 680);

    creating_ = !lspass::Vault::exists(vault_path());

    // ---------- locked page ----------
    locked_box_.set_margin(32);
    locked_box_.set_valign(Gtk::Align::CENTER);

    lock_title_.set_markup("<span size='xx-large' weight='bold'>🔒 lsPass</span>");
    locked_box_.append(lock_title_);

    auto subtitle = Gtk::make_managed<Gtk::Label>(
        creating_ ? "Create a master password to initialise your vault."
                  : "Enter your master password to unlock.");
    subtitle->set_wrap(true);
    locked_box_.append(*subtitle);

    pw_entry_.property_placeholder_text().set_value("Master password");
    pw_entry_.set_property("show-peek-icon", true);
    pw_entry_.signal_activate().connect([this] { on_unlock_clicked(); });
    locked_box_.append(pw_entry_);

    if (creating_) {
        pw_confirm_.property_placeholder_text().set_value("Confirm master password");
        pw_confirm_.set_property("show-peek-icon", true);
        pw_confirm_.signal_activate().connect([this] { on_unlock_clicked(); });
        locked_box_.append(pw_confirm_);
        unlock_btn_.set_label("Create Vault");
    }
    unlock_btn_.add_css_class("suggested-action");
    unlock_btn_.signal_clicked().connect([this] { on_unlock_clicked(); });
    locked_box_.append(unlock_btn_);

    lock_status_.add_css_class("error");
    lock_status_.set_wrap(true);
    locked_box_.append(lock_status_);

    stack_.add(locked_box_, "locked");

    // ---------- unlocked page ----------
    unlocked_box_.set_margin(12);

    search_.set_placeholder_text("Search entries…");
    search_.signal_search_changed().connect(
        [this] { refresh_entries(search_.get_text()); });
    unlocked_box_.append(search_);

    scroll_.set_vexpand(true);
    list_.set_selection_mode(Gtk::SelectionMode::NONE);
    list_.add_css_class("boxed-list");
    scroll_.set_child(list_);
    unlocked_box_.append(scroll_);
    unlocked_box_.append(empty_label_);

    auto addbar = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 8);
    addbar->set_halign(Gtk::Align::CENTER);
    auto mk_add = [&](const char* label, int type) {
        auto b = Gtk::make_managed<Gtk::Button>(label);
        b->signal_clicked().connect([this, type] { on_add(type); });
        addbar->append(*b);
    };
    mk_add("＋ Login", 0);
    mk_add("＋ Note", 1);
    mk_add("＋ API Key", 2);
    unlocked_box_.append(*addbar);

    stack_.add(unlocked_box_, "unlocked");
    stack_.set_visible_child("locked");

    // ---------- header bar ----------
    auto header = Gtk::make_managed<Gtk::HeaderBar>();
    auto lock_btn = Gtk::make_managed<Gtk::Button>("Lock");
    lock_btn->signal_clicked().connect([this] { on_lock(); });
    header->pack_end(*lock_btn);
    auto master_btn = Gtk::make_managed<Gtk::Button>("Master Password");
    master_btn->signal_clicked().connect([this] { on_change_master(); });
    header->pack_end(*master_btn);
    auto settings_btn = Gtk::make_managed<Gtk::Button>("Settings");
    settings_btn->signal_clicked().connect([this] { on_settings(); });
    header->pack_end(*settings_btn);
    set_titlebar(*header);

    // Header actions only make sense once unlocked.
    stack_.property_visible_child_name().signal_changed().connect(
        [this, lock_btn, master_btn, settings_btn] {
        const bool unlocked = stack_.get_visible_child_name() == "unlocked";
        lock_btn->set_visible(unlocked);
        master_btn->set_visible(unlocked);
        settings_btn->set_visible(unlocked);
    });
    lock_btn->set_visible(false);
    master_btn->set_visible(false);
    settings_btn->set_visible(false);

    status_.add_css_class("dim-label");
    status_.set_margin(6);
    root_box_.append(stack_);
    stack_.set_vexpand(true);
    root_box_.append(status_);
    set_child(root_box_);
}

std::string MainWindow::vault_path() {
    return Glib::get_user_data_dir() + "/lspass/vault.db";
}

void MainWindow::show_lock_error(const Glib::ustring& msg) {
    lock_status_.set_text(msg);
}

void MainWindow::on_unlock_clicked() {
    lock_status_.set_text("");
    const auto pw = pw_entry_.get_text().raw();
    if (pw.empty()) { show_lock_error("Password cannot be empty."); return; }

    unlock_btn_.set_sensitive(false);
    try {
        if (creating_) {
            if (pw != pw_confirm_.get_text().raw()) {
                show_lock_error("Passwords do not match.");
                unlock_btn_.set_sensitive(true);
                return;
            }
            if (pw.size() < 8) {
                show_lock_error("Use at least 8 characters for the master password.");
                unlock_btn_.set_sensitive(true);
                return;
            }
            vault_.emplace(lspass::Vault::create(vault_path(), pw));
        } else {
            vault_.emplace(lspass::Vault::open(vault_path(), pw));
        }
    } catch (const lspass::WrongPassword&) {
        show_lock_error("Wrong master password.");
        unlock_btn_.set_sensitive(true);
        return;
    } catch (const std::exception& e) {
        show_lock_error(Glib::ustring{"Error: "} + e.what());
        unlock_btn_.set_sensitive(true);
        return;
    }
    unlock_btn_.set_sensitive(true);

    // Clear password fields promptly — minimise plaintext lifetime.
    pw_entry_.set_text("");
    pw_confirm_.set_text("");

    load_settings();
    refresh_entries();
    stack_.set_visible_child("unlocked");
    search_.grab_focus();
}

void MainWindow::on_lock() {
    vault_.reset(); // DEK wiped by SecureBytes destructor
    search_.set_text("");
    refresh_entries();
    stack_.set_visible_child("locked");
    pw_entry_.grab_focus();
}

void MainWindow::refresh_entries(const Glib::ustring& filter) {
    while (auto* row = list_.get_row_at_index(0))
        list_.remove(*row);
    if (!vault_) { empty_label_.set_visible(false); return; }

    auto entries = vault_->list_entries(filter);
    empty_label_.set_visible(entries.empty());

    for (const auto& e : entries) {
        auto box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 10);
        box->set_margin_top(8);
        box->set_margin_bottom(8);
        box->set_margin_start(10);
        box->set_margin_end(10);

        auto text = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::VERTICAL, 2);
        text->set_hexpand(true);
        text->set_halign(Gtk::Align::START);

        Glib::ustring title = "<b>" + Glib::Markup::escape_text(e.title) + "</b>"
            + "  <span alpha='60%' size='small'>"
            + lspass::entry_type_name(e.type) + "</span>";
        auto tl = Gtk::make_managed<Gtk::Label>();
        tl->set_markup(title);
        tl->set_halign(Gtk::Align::START);
        text->append(*tl);

        Glib::ustring sub = e.username;
        if (!e.url.empty()) sub += (sub.empty() ? "" : "  ·  ") + e.url;
        auto sl = Gtk::make_managed<Gtk::Label>(sub);
        sl->set_halign(Gtk::Align::START);
        sl->add_css_class("dim-label");
        sl->set_ellipsize(Pango::EllipsizeMode::END);
        text->append(*sl);
        box->append(*text);

        // Copy popup: pick exactly which field to copy.
        auto copy_btn = Gtk::make_managed<Gtk::Button>("Copy ▾");
        copy_btn->set_valign(Gtk::Align::CENTER);
        auto pop = Gtk::make_managed<Gtk::Popover>();
        pop->set_parent(*copy_btn);
        auto popbox = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::VERTICAL, 0);
        auto add_copy = [&](const Glib::ustring& label, const std::string& value,
                            bool sensitive) {
            auto b = Gtk::make_managed<Gtk::Button>(label);
            b->add_css_class("flat");
            b->set_halign(Gtk::Align::FILL);
            b->get_child()->set_halign(Gtk::Align::START);
            b->signal_clicked().connect([this, pop, value, sensitive] {
                pop->popdown();
                copy_to_clipboard(value, sensitive);
            });
            popbox->append(*b);
        };
        if (!e.username.empty())
            add_copy("Username", e.username, false);
        {
            const char* what = e.type == lspass::EntryType::Login  ? "Password" :
                               e.type == lspass::EntryType::ApiKey ? "API Key"  :
                                                                     "Note content";
            if (!e.secret.empty())
                add_copy(what, e.secret, true);
        }
        if (!e.url.empty())
            add_copy("URL", e.url, false);
        if (!e.notes.empty())
            add_copy("Additional notes", e.notes, true);
        pop->set_child(*popbox);
        copy_btn->signal_clicked().connect([pop] { pop->popup(); });
        box->append(*copy_btn);

        auto mk_btn = [&](const char* label, auto fn) {
            auto b = Gtk::make_managed<Gtk::Button>(label);
            b->set_valign(Gtk::Align::CENTER);
            b->signal_clicked().connect([this, e, fn] { (this->*fn)(e); });
            box->append(*b);
        };
        mk_btn("Edit", &MainWindow::on_edit);
        mk_btn("Delete", &MainWindow::on_delete);

        list_.append(*box);
    }
}

void MainWindow::on_add(int type) {
    lspass::Entry e;
    e.type = static_cast<lspass::EntryType>(type);
    auto* dlg = Gtk::make_managed<EntryDialog>(
        *this, e, true, gen_opts_,
        [this](lspass::Entry ne) {
            try {
                vault_->add_entry(std::move(ne));
                refresh_entries(search_.get_text());
                show_toast("Entry added");
            } catch (const std::exception& ex) {
                show_toast(Glib::ustring{"Save failed: "} + ex.what());
            }
        });
    dlg->present();
}

void MainWindow::on_edit(const lspass::Entry& e) {
    auto* dlg = Gtk::make_managed<EntryDialog>(
        *this, e, false, gen_opts_,
        [this](lspass::Entry ue) {
            try {
                vault_->update_entry(ue);
                refresh_entries(search_.get_text());
                show_toast("Entry updated");
            } catch (const std::exception& ex) {
                show_toast(Glib::ustring{"Save failed: "} + ex.what());
            }
        });
    dlg->present();
}

void MainWindow::on_delete(const lspass::Entry& e) {
    auto dlg = Gtk::AlertDialog::create(
        "Delete “" + Glib::Markup::escape_text(e.title) + "”? This cannot be undone.");
    dlg->set_buttons({"Cancel", "Delete"});
    dlg->set_default_button(0);
    dlg->set_cancel_button(0);
    dlg->choose(*this, [this, dlg, id = e.id](const Glib::RefPtr<Gio::AsyncResult>& res) {
        try {
            if (dlg->choose_finish(res) == 1) {
                vault_->delete_entry(id);
                refresh_entries(search_.get_text());
                show_toast("Entry deleted");
            }
        } catch (...) { /* dismissed */ }
    });
}

void MainWindow::copy_to_clipboard(const std::string& text, bool sensitive) {
    auto display = Gdk::Display::get_default();
    if (!display) return;
    display->get_clipboard()->set_text(text);
    show_toast(sensitive ? "Copied — clipboard clears in 30 s" : "Copied");

    if (!sensitive) return;
    // Auto-clear the clipboard so secrets do not linger.
    Glib::signal_timeout().connect_seconds_once(
        [display, expected = text] {
            auto cb = display->get_clipboard();
            // Only clear if the clipboard still holds our secret.
            cb->read_text_async([cb, expected](const Glib::RefPtr<Gio::AsyncResult>& res) {
                try {
                    if (cb->read_text_finish(res) == expected)
                        cb->set_text("");
                } catch (...) {}
            });
        }, 30);
}

void MainWindow::on_change_master() {
    auto dlg = Gtk::make_managed<Gtk::Window>();
    dlg->set_title("Change Master Password");
    dlg->set_transient_for(*this);
    dlg->set_modal(true);

    auto box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::VERTICAL, 10);
    box->set_margin(16);
    auto cur = Gtk::make_managed<Gtk::PasswordEntry>();
    cur->property_placeholder_text().set_value("Current password");
    auto nw = Gtk::make_managed<Gtk::PasswordEntry>();
    nw->property_placeholder_text().set_value("New password (min 8 chars)");
    auto cf = Gtk::make_managed<Gtk::PasswordEntry>();
    cf->property_placeholder_text().set_value("Confirm new password");
    auto err = Gtk::make_managed<Gtk::Label>();
    err->add_css_class("error");
    auto ok = Gtk::make_managed<Gtk::Button>("Change");
    ok->add_css_class("suggested-action");

    box->append(*cur); box->append(*nw); box->append(*cf);
    box->append(*err); box->append(*ok);
    dlg->set_child(*box);

    ok->signal_clicked().connect([this, dlg, cur, nw, cf, err] {
        err->set_text("");
        if (nw->get_text().size() < 8) { err->set_text("New password too short."); return; }
        if (nw->get_text() != cf->get_text()) { err->set_text("Passwords do not match."); return; }
        try {
            // Verify current password against the on-disk header first.
            auto check = lspass::Vault::open(vault_path(), cur->get_text().raw());
            (void)check;
            vault_->change_master_password(nw->get_text().raw());
            dlg->close();
            show_toast("Master password changed");
        } catch (const lspass::WrongPassword&) {
            err->set_text("Current password is wrong.");
        } catch (const std::exception& e) {
            err->set_text(Glib::ustring{"Error: "} + e.what());
        }
    });
    dlg->present();
}

void MainWindow::load_settings() {
    if (!vault_) return;
    auto b = [&](const char* k, bool def) {
        const std::string v = vault_->get_setting(k, def ? "1" : "0");
        return v == "1";
    };
    gen_opts_.length       = std::stoi(vault_->get_setting("gen_length", "20"));
    gen_opts_.lower        = b("gen_lower", true);
    gen_opts_.upper        = b("gen_upper", true);
    gen_opts_.digits       = b("gen_digits", true);
    gen_opts_.symbols      = b("gen_symbols", true);
    gen_opts_.ambiguous_ok = b("gen_ambiguous", false);
}

void MainWindow::on_settings() {
    auto dlg = Gtk::make_managed<Gtk::Window>();
    dlg->set_title("Settings — Password Generator");
    dlg->set_transient_for(*this);
    dlg->set_modal(true);

    auto grid = Gtk::make_managed<Gtk::Grid>();
    grid->set_margin(16);
    grid->set_row_spacing(10);
    grid->set_column_spacing(10);

    // -- Appearance (applies immediately, stored outside the vault) --
    auto appear_l = Gtk::make_managed<Gtk::Label>();
    appear_l->set_markup("<b>Appearance</b>");
    appear_l->set_halign(Gtk::Align::START);
    grid->attach(*appear_l, 0, 0, 2);
    auto dark_sw = Gtk::make_managed<Gtk::Switch>();
    dark_sw->set_active(load_dark_pref());
    dark_sw->set_halign(Gtk::Align::END);
    dark_sw->set_valign(Gtk::Align::CENTER);
    dark_sw->property_active().signal_changed().connect([dark_sw] {
        const bool dark = dark_sw->get_active();
        apply_theme(dark);
        save_dark_pref(dark);
    });
    auto dark_l = Gtk::make_managed<Gtk::Label>("Dark mode");
    dark_l->set_halign(Gtk::Align::START);
    grid->attach(*dark_l, 0, 1);
    grid->attach(*dark_sw, 1, 1);

    auto gen_l = Gtk::make_managed<Gtk::Label>();
    gen_l->set_markup("<b>Password Generator</b>");
    gen_l->set_halign(Gtk::Align::START);
    gen_l->set_margin_top(8);
    grid->attach(*gen_l, 0, 2, 2);

    auto len_adj = Gtk::Adjustment::create(gen_opts_.length, 4, 128, 1, 8);
    auto len = Gtk::make_managed<Gtk::SpinButton>(len_adj);
    auto ll = Gtk::make_managed<Gtk::Label>("Length");
    ll->set_halign(Gtk::Align::START);
    grid->attach(*ll, 0, 3);
    grid->attach(*len, 1, 3);

    auto lower = Gtk::make_managed<Gtk::CheckButton>("Lowercase (a-z)");
    lower->set_active(gen_opts_.lower);
    auto upper = Gtk::make_managed<Gtk::CheckButton>("Uppercase (A-Z)");
    upper->set_active(gen_opts_.upper);
    auto digits = Gtk::make_managed<Gtk::CheckButton>("Digits (0-9)");
    digits->set_active(gen_opts_.digits);
    auto symbols = Gtk::make_managed<Gtk::CheckButton>("Symbols (!@#$…)");
    symbols->set_active(gen_opts_.symbols);
    auto ambiguous = Gtk::make_managed<Gtk::CheckButton>(
        "Allow ambiguous characters (I, l, 1, O, 0)");
    ambiguous->set_active(gen_opts_.ambiguous_ok);

    grid->attach(*lower, 0, 4, 2);
    grid->attach(*upper, 0, 5, 2);
    grid->attach(*digits, 0, 6, 2);
    grid->attach(*symbols, 0, 7, 2);
    grid->attach(*ambiguous, 0, 8, 2);

    auto entropy = Gtk::make_managed<Gtk::Label>();
    entropy->add_css_class("dim-label");
    entropy->set_halign(Gtk::Align::START);
    grid->attach(*entropy, 0, 9, 2);

    auto err = Gtk::make_managed<Gtk::Label>();
    err->add_css_class("error");
    grid->attach(*err, 0, 10, 2);

    auto update_entropy = [=] {
        lspass::PasswordOptions o;
        o.length = len->get_value_as_int();
        o.lower = lower->get_active(); o.upper = upper->get_active();
        o.digits = digits->get_active(); o.symbols = symbols->get_active();
        if (!o.lower && !o.upper && !o.digits && !o.symbols) {
            entropy->set_text("");
            err->set_text("Enable at least one character class.");
            return;
        }
        err->set_text("");
        entropy->set_text(Glib::ustring::compose(
            "≈ %1 bits of entropy per generated password",
            static_cast<int>(lspass::password_entropy_bits(o))));
    };
    len->signal_value_changed().connect([update_entropy] { update_entropy(); });
    for (auto* cb : {lower, upper, digits, symbols})
        cb->signal_toggled().connect([update_entropy] { update_entropy(); });
    update_entropy();

    auto btns = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 8);
    btns->set_halign(Gtk::Align::END);
    auto cancel = Gtk::make_managed<Gtk::Button>("Cancel");
    cancel->signal_clicked().connect([dlg] { dlg->close(); });
    auto save = Gtk::make_managed<Gtk::Button>("Save");
    save->add_css_class("suggested-action");
    save->signal_clicked().connect(
        [this, dlg, len, lower, upper, digits, symbols, ambiguous, err] {
            if (!lower->get_active() && !upper->get_active() &&
                !digits->get_active() && !symbols->get_active()) {
                err->set_text("Enable at least one character class.");
                return;
            }
            gen_opts_.length       = len->get_value_as_int();
            gen_opts_.lower        = lower->get_active();
            gen_opts_.upper        = upper->get_active();
            gen_opts_.digits       = digits->get_active();
            gen_opts_.symbols      = symbols->get_active();
            gen_opts_.ambiguous_ok = ambiguous->get_active();
            if (vault_) {
                vault_->set_setting("gen_length", std::to_string(gen_opts_.length));
                auto bs = [this](const char* k, bool v) {
                    vault_->set_setting(k, v ? "1" : "0");
                };
                bs("gen_lower", gen_opts_.lower);
                bs("gen_upper", gen_opts_.upper);
                bs("gen_digits", gen_opts_.digits);
                bs("gen_symbols", gen_opts_.symbols);
                bs("gen_ambiguous", gen_opts_.ambiguous_ok);
            }
            dlg->close();
            show_toast("Settings saved");
        });
    btns->append(*cancel);
    btns->append(*save);
    grid->attach(*btns, 0, 11, 2);

    dlg->set_child(*grid);
    dlg->present();
}

void MainWindow::show_toast(const Glib::ustring& msg) {
    status_.set_text(msg);
    if (status_timeout_)
        g_source_remove(status_timeout_);
    status_timeout_ = g_timeout_add_seconds_once(4, [](gpointer self) {
        static_cast<MainWindow*>(self)->status_.set_text("");
    }, this);
}
