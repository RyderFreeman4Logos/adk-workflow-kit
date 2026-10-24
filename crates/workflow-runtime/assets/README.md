# Language identification asset

`lid.176.ftz` is the unmodified fastText language identification model published by Facebook AI Research, trained on Wikipedia, Tatoeba and SETimes. It has 176 language labels. The 938,013-byte file has SHA-256 `8f3472cfe8738a7b6099e8e999c3cbfae0dcd15696aac7d7738a8039db603e83`.

Source: https://dl.fbaipublicfiles.com/fasttext/supervised-models/lid.176.ftz
Model documentation: https://fasttext.cc/docs/en/language-identification.html
License: Creative Commons Attribution-ShareAlike 3.0 Unported, reproduced in `lid.176.LICENSE.txt` (https://creativecommons.org/licenses/by-sa/3.0/). The model license is separate from the crate code license. No changes were made to the model.

The bytes are embedded at build time and verified before loading into a sealed memory file. Installed executables do not require a source checkout, external model path or network. Model scores are uncalibrated ranking evidence, not guarantees of language identity. Shared-Han names can be ambiguous. Keep model identity, attribution policy version and qualification fixtures synchronized when replacing these bytes.
