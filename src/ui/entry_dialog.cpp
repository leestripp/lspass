#include "entry_dialog.hpp"
#include "generator.hpp"

EntryDialog::EntryDialog(Gtk::Window& parent, lspass::Entry entry, bool is_new,
                         const lspass::PasswordOptions& gen_opts,
                         sigc::slot<void(lspass::Entry)> on_save)
    : entry_(std::move(entry)), gen_opts_(gen_opts), is_new_(is_new),
      on_save_(std::move(on_save)),
      type_(Gtk::StringList::create(std::vector<Glib::ustring>{
          "Login", "Secure Note", "API Key"})) {

    set_title(is_new_ ? "Add Entry" : "Edit Entry");
    set_transient_for(parent);
    set_modal(true);
    set_default_size(420, 560);

    auto grid = Gtk::make_managed<Gtk::Grid>();
    grid->set_margin(16);
    grid->set_row_spacing(10);
    grid->set_column_spacing(10);

    int row = 0;
    auto add_row = [&](const char* label, Gtk::Widget& w) {
        auto l = Gtk::make_managed<Gtk::Label>(label);
        l->set_halign(Gtk::Align::START);
        grid->attach(*l, 0, row);
        w.set_hexpand(true);
        grid->attach(w, 1, row);
        ++row;
    };

    type_.set_selected(static_cast<guint>(static_cast<int>(entry_.type)));
    add_row("Type", type_);

    title_.set_text(entry_.title);
    title_.set_placeholder_text("e.g. GitHub, Bank, Production DB…");
    add_row("Title", title_);

    username_.set_text(entry_.username);
    username_.set_placeholder_text("username / email / key name");
    add_row("Username", username_);

    url_.set_text(entry_.url);
    url_.set_placeholder_text("https://…");
    add_row("URL", url_);

    secret_.set_text(entry_.secret);
    secret_.set_property("show-peek-icon", true);
    secret_.set_hexpand(true);
    {
        auto l = Gtk::make_managed<Gtk::Label>("Secret");
        l->set_halign(Gtk::Align::START);
        grid->attach(*l, 0, row);
        auto box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 6);
        secret_.set_hexpand(true);
        box->append(secret_);
        auto gen = Gtk::make_managed<Gtk::Button>("Generate");
        gen->set_tooltip_text("Generate a strong random password");
        gen->signal_clicked().connect([this] { on_generate_secret(); });
        box->append(*gen);
        grid->attach(*box, 1, row);
        ++row;
    }

    auto nl = Gtk::make_managed<Gtk::Label>("Notes");
    nl->set_halign(Gtk::Align::START);
    nl->set_valign(Gtk::Align::START);
    grid->attach(*nl, 0, row);
    auto sw = Gtk::make_managed<Gtk::ScrolledWindow>();
    sw->set_min_content_height(120);
    sw->set_vexpand(true);
    notes_.get_buffer()->set_text(entry_.notes);
    notes_.set_wrap_mode(Gtk::WrapMode::WORD);
    sw->set_child(notes_);
    grid->attach(*sw, 1, row);
    ++row;

    error_.add_css_class("error");
    grid->attach(error_, 0, row, 2);
    ++row;

    auto btns = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 8);
    btns->set_halign(Gtk::Align::END);
    auto cancel = Gtk::make_managed<Gtk::Button>("Cancel");
    cancel->signal_clicked().connect([this] { close(); });
    auto save = Gtk::make_managed<Gtk::Button>(is_new_ ? "Add" : "Save");
    save->add_css_class("suggested-action");
    save->signal_clicked().connect([this] { this->on_save(); });
    btns->append(*cancel);
    btns->append(*save);
    grid->attach(*btns, 0, row, 2);

    set_child(*grid);
}

void EntryDialog::on_generate_secret() {
    try {
        secret_.set_text(lspass::generate_password(gen_opts_));
        secret_.set_tooltip_text(Glib::ustring::compose(
            "%1 bits of entropy", static_cast<int>(lspass::password_entropy_bits(gen_opts_))));
        secret_.grab_focus();
    } catch (const std::exception& e) {
        error_.set_text(Glib::ustring{"Generator: "} + e.what());
    }
}

void EntryDialog::on_save() {
    entry_.type = static_cast<lspass::EntryType>(
        static_cast<int>(type_.get_selected()));
    entry_.title    = title_.get_text();
    entry_.username = username_.get_text();
    entry_.url      = url_.get_text();
    entry_.secret   = secret_.get_text();
    auto buf = notes_.get_buffer();
    entry_.notes    = buf->get_text(buf->begin(), buf->end());

    if (entry_.title.empty()) {
        error_.set_text("Title is required.");
        return;
    }
    on_save_(std::move(entry_));
    close();
}
