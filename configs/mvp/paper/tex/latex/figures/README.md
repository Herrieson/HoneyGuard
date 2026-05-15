# TraceProbe Figure Drop-In Directory

Put final paper figure PDFs in this directory with these exact filenames:

```text
fig1_pipeline.pdf
fig2_taxonomy.pdf
fig3_main_results.pdf
fig4_internal_authority.pdf
fig5_replay_localization.pdf
fig6_compositional.pdf
```

The TeX draft uses `\IfFileExists`, so missing files render as boxed placeholders.
When a file exists here, it is included automatically.

Optional appendix case figures can also be placed here:

```text
appendix_a6_transient_repeated_insert_remove.pdf
appendix_a7_b3_internal_authority_case.pdf
```

See `configs/mvp/paper/figure_drawing_guide.md` for panel layouts, data sources,
and caption requirements.
