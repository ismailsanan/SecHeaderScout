package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.manual.ProfileGrouper;
import io.github.ismailsanan.secheaderscout.model.HeaderProfile;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static io.github.ismailsanan.secheaderscout.testsupport.Results.missing;
import static io.github.ismailsanan.secheaderscout.testsupport.Results.result;
import static io.github.ismailsanan.secheaderscout.testsupport.Results.weak;
import static org.junit.jupiter.api.Assertions.assertEquals;

/** The "By profile" table: one row per host + path group, showing the missing header names. */
class ProfilesTableModelTest {

    @Test
    void rowsShowSensitivityHostPathSizeMissingHeadersAndSeverity() {
        List<ProfileGrouper.Analysed> analysed = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            analysed.add(new ProfileGrouper.Analysed("e.example", result("https://e.example/api/p" + i,
                    List.of(missing("Referrer-Policy"), missing("Content-Security-Policy")), Set.of())));
        }
        analysed.add(new ProfileGrouper.Analysed("e.example",
                result("https://e.example/login", List.of(weak("X-Frame-Options", "x")), Set.of())));
        List<HeaderProfile> profiles = ProfileGrouper.group(analysed);

        ProfilesTableModel model = new ProfilesTableModel();
        model.setRows(profiles);

        assertEquals(2, model.getRowCount());
        assertEquals("LOGIN", model.getValueAt(0, ProfilesTableModel.COL_FLAG), "sensitive groups first");
        assertEquals("/login", model.getValueAt(0, ProfilesTableModel.COL_PATH));
        assertEquals(1, model.getValueAt(0, 5));

        assertEquals("", model.getValueAt(1, ProfilesTableModel.COL_FLAG));
        assertEquals("e.example", model.getValueAt(1, 1));
        assertEquals("/api/*", model.getValueAt(1, ProfilesTableModel.COL_PATH));
        assertEquals(3, model.getValueAt(1, 3));
        assertEquals("Referrer-Policy, Content-Security-Policy", model.getValueAt(1, ProfilesTableModel.COL_MISSING));
        assertEquals("INFORMATION", model.getValueAt(1, 6));
        assertEquals(Integer.class, model.getColumnClass(3));
    }
}
