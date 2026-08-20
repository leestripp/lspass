#include "main_window.hpp"
#include <gtkmm.h>

int main(int argc, char** argv) {
    auto app = Gtk::Application::create("com.lspass.App",
                                        Gio::Application::Flags::NONE);
    return app->make_window_and_run<MainWindow>(argc, argv);
}
